"""
normalization/normalizer.py  (Phase 5)

Detects common obfuscation/encoding techniques used to slip sensitive
content past naive plaintext scanners, decodes them, and RE-RUNS the Phase 4
deterministic detectors against the decoded content. This is the piece that
turns "regex on raw bytes" into something that can catch a base64-encoded
credit card number pasted into a chat message, or a secret buried inside a
gzip-compressed, then base64-encoded, blob.

Techniques covered:
  1. Base64                — arbitrary runs of base64 alphabet characters.
  2. URL / percent-encoding — %XX escape sequences.
  3. JSON-embedded content  — sensitive data hiding inside a JSON string value
                               (e.g. {"note": "card 4111111111111111"}).
  4. Gzip / Zip compression — magic-byte detected, decompressed in memory.

Design choices (see docs/NORMALIZATION.md for full rationale):
  - Recursion is bounded by `max_recursion_depth` (config) to prevent
    decompression-bomb style resource exhaustion from a malicious or
    corrupt input; depth is decremented on every layer unwrapped regardless
    of technique.
  - A decoded byte sequence is only treated as "text worth rescanning" if
    its printable-character ratio clears `min_printable_ratio_after_decode`
    — this avoids wasting cycles running regex detectors against decoded
    binary noise that happened to Base64-decode without erroring.
"""

from __future__ import annotations

import base64
import gzip
import json
import re
import string
import zipfile
import io
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import unquote

import yaml

from common.event_schema import DetectionResult, ObfuscationResult

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "detection_policy.yaml"

_PRINTABLE = set(bytes(string.printable, "ascii"))
_BASE64_CHARS = re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}")
_URL_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")

# type alias: a function with the same signature as detectors.engine.run_all
DetectorRunner = Callable[..., list[DetectionResult]]


def load_normalization_config(policy_path: str | Path = DEFAULT_POLICY_PATH) -> dict[str, Any]:
    with open(policy_path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    return policy.get("normalization", {
        "max_recursion_depth": 3,
        "min_base64_run_length": 40,
        "min_printable_ratio_after_decode": 0.85,
    })


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable_count = sum(1 for b in data if b in _PRINTABLE)
    return printable_count / len(data)


# ---------------------------------------------------------------------------
# Individual technique detectors — each returns decoded text, or None if the
# technique was not present / did not yield plausible text.
# ---------------------------------------------------------------------------

_BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{4,}={0,2}")


def try_decode_base64(text: str, min_run_length: int, min_printable_ratio: float) -> list[str]:
    """
    Find base64-looking tokens and decode the plausible ones.

    The length filter is applied to the TOTAL captured token (letters/digits
    plus any trailing '=' padding), not just the non-padding run — a 40-char
    token that happens to end in "==" only has 38 alphabet characters, and
    checking the alphabet-only count against min_run_length would incorrectly
    discard it. See tests/test_normalizer.py for the regression case.
    """
    decoded_candidates = []
    for m in _BASE64_TOKEN_RE.finditer(text):
        candidate = m.group(0)
        if len(candidate) < min_run_length:
            continue
        # base64 payloads are 4-char aligned; trim any trailing partial group
        usable_len = len(candidate) - (len(candidate) % 4)
        trimmed = candidate[:usable_len]
        if len(trimmed) < 4:
            continue
        try:
            raw = base64.b64decode(trimmed, validate=True)
        except Exception:
            continue
        if _printable_ratio(raw) >= min_printable_ratio:
            try:
                decoded_candidates.append(raw.decode("utf-8"))
            except UnicodeDecodeError:
                decoded_candidates.append(raw.decode("latin-1"))
    return decoded_candidates


def try_decode_url_encoding(text: str) -> Optional[str]:
    if not _URL_ENCODED_RE.search(text):
        return None
    decoded = unquote(text)
    return decoded if decoded != text else None


def try_extract_json_strings(text: str) -> list[str]:
    """
    Attempt json.loads on the whole text; if that fails, look for the first
    balanced {...} or [...] span and try that. Returns all string leaf
    values found, which are what get rescanned (this is where a payload
    like {"note": "<sensitive content>"} gets caught).
    """
    candidates_to_try = [text]
    brace_match = re.search(r"[\{\[].*[\}\]]", text, re.DOTALL)
    if brace_match:
        candidates_to_try.append(brace_match.group(0))

    for candidate in candidates_to_try:
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
        return _walk_json_strings(parsed)
    return []


def _walk_json_strings(node: Any) -> list[str]:
    found = []
    if isinstance(node, str):
        found.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            found.extend(_walk_json_strings(v))
    elif isinstance(node, list):
        for v in node:
            found.extend(_walk_json_strings(v))
    return found


def try_decompress(content_bytes: bytes, min_printable_ratio: float) -> Optional[str]:
    if content_bytes[:2] == b"\x1f\x8b":
        try:
            raw = gzip.decompress(content_bytes)
        except Exception:
            return None
    elif content_bytes[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(content_bytes)) as zf:
                names = zf.namelist()
                if not names:
                    return None
                raw = zf.read(names[0])
        except Exception:
            return None
    else:
        return None

    if _printable_ratio(raw) < min_printable_ratio:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def normalize_and_rescan(
    content: str | bytes,
    detector_runner: DetectorRunner,
    policy_path: str | Path = DEFAULT_POLICY_PATH,
    _depth: int = 0,
) -> list[ObfuscationResult]:
    """
    Try every obfuscation technique against `content`. For each technique
    that yields plausible decoded text, run `detector_runner` (normally
    detectors.engine.run_all) against the decoded text and recurse (bounded
    by max_recursion_depth) in case of nested encoding.
    """
    cfg = load_normalization_config(policy_path)
    max_depth = cfg.get("max_recursion_depth", 3)
    min_run = cfg.get("min_base64_run_length", 40)
    min_ratio = cfg.get("min_printable_ratio_after_decode", 0.85)

    results: list[ObfuscationResult] = []
    if _depth >= max_depth:
        return results

    text = content if isinstance(content, str) else None
    content_bytes = content if isinstance(content, bytes) else (content.encode("utf-8", errors="ignore") if text else b"")

    # 1. Compression (bytes-first, since text won't have compression magic bytes)
    decompressed = try_decompress(content_bytes, min_ratio) if content_bytes else None
    if decompressed:
        results.append(_build_result("gzip_or_zip", decompressed, detector_runner, policy_path, _depth))

    if text is not None:
        # 2. Base64
        for decoded in try_decode_base64(text, min_run, min_ratio):
            results.append(_build_result("base64", decoded, detector_runner, policy_path, _depth))

        # 3. URL encoding
        url_decoded = try_decode_url_encoding(text)
        if url_decoded:
            results.append(_build_result("url_encoding", url_decoded, detector_runner, policy_path, _depth))

        # 4. JSON-embedded strings
        json_strings = try_extract_json_strings(text)
        for s in json_strings:
            if s and s != text:
                results.append(_build_result("json_embedded", s, detector_runner, policy_path, _depth))

    return results


def _build_result(
    technique: str,
    decoded_text: str,
    detector_runner: DetectorRunner,
    policy_path: str | Path,
    depth: int,
) -> ObfuscationResult:
    rescanned = detector_runner(decoded_text)
    nested = normalize_and_rescan(decoded_text, detector_runner, policy_path, _depth=depth + 1)
    nested_matches = [d for n in nested for d in n.rescanned_detections]
    return ObfuscationResult(
        technique=technique,
        found=True,
        layers=1 + max((n.layers for n in nested), default=0),
        decoded_excerpt=decoded_text[:200],
        rescanned_detections=rescanned + nested_matches,
    )
