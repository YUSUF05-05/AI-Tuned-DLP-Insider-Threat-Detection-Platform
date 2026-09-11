# PHASE 5 — CONTENT NORMALIZATION & OBFUSCATION DETECTION

## 🎯 Objective

Catch sensitive content that Phase 4's detectors would miss because it's
been base64-encoded, URL-encoded, embedded inside a JSON string value, or
compressed (gzip/zip) — satisfying threat-model requirement DR6 and directly
covering scenario S5 (`docs/THREAT_MODEL.md`). This is the phase that turns
"regex on raw bytes" into something that survives basic evasion.

## 🧠 Concept

Four techniques, one orchestrator (`normalize_and_rescan()`), recursive up to
a bounded depth. The core idea: for each technique, try to decode; if the
decoded bytes are plausibly text (checked via a printable-character-ratio
threshold, not just "didn't throw an exception"), **re-run the full Phase 4
detector suite against the decoded content**, and recurse — because
obfuscation can be layered (a card number, base64-encoded, embedded as a
JSON string value, is a real, two-layer case this project actually tests).

**Bounded recursion is a security property, not just a performance one.**
`max_recursion_depth` (default 3, in `config/detection_policy.yaml`) exists
specifically so a malicious or corrupt input can't trigger unbounded
work — this is the same class of concern as a decompression-bomb defense,
scaled to this project's actual risk (nothing here processes untrusted files
from strangers, but the discipline is worth having regardless).

**Printable-ratio gating avoids wasted work.** Not every string that
*decodes without error* is meaningful text — plenty of binary data
"successfully" base64-decodes into garbage bytes. Rescanning garbage with
five regex detectors on every single incidental base64-looking substring in
a document would be wasteful and noisy. `min_printable_ratio_after_decode`
(default 0.85) filters that out before it ever reaches Phase 4's detectors.

## 🏗️ Architecture

```
content (str | bytes)
      │
      ▼
normalize_and_rescan() ── depth < max_recursion_depth? ──No──▶ stop
      │ Yes
      ├─▶ try_decompress()        (gzip / zip magic bytes)
      ├─▶ try_decode_base64()     (regex-found runs, 4-byte-aligned)
      ├─▶ try_decode_url_encoding() (%XX sequences)
      └─▶ try_extract_json_strings() (json.loads, walk string leaves)
             │ (each successful decode)
             ▼
      detector_runner(decoded_text)         <- Phase 4's run_all()
             │
             ▼
      normalize_and_rescan(decoded_text, ..., depth+1)   <- recurse
```
`ObfuscationResult.layers` reports how many encodings were actually
unwrapped for a given hit, so a single-layer base64 string and a
base64-inside-JSON payload are distinguishable in the output, not just both
reported as "obfuscated: yes."

## 📁 Files

```
normalization/normalizer.py
tests/test_normalizer.py
```

## ⚙️ Configuration

```yaml
normalization:
  max_recursion_depth: 3
  min_base64_run_length: 40
  min_printable_ratio_after_decode: 0.85
```

## 💻 Commands

```powershell
python -m pytest tests/test_normalizer.py -v
```
Try it directly:
```powershell
python -c "
import base64
from detectors.engine import run_all
from normalization.normalizer import normalize_and_rescan
payload = base64.b64encode(b'card on file 4111111111111111').decode()
results = normalize_and_rescan(f'see attached: {payload}', run_all)
for r in results:
    print(r.technique, r.found, r.layers, [d.detector for d in r.rescanned_detections if d.matched])
"
```

## 🧩 Implementation

### `normalization/normalizer.py` — complete file
```python
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
```

## 🧪 Testing

Real, current output:
```
$ python -m pytest tests/test_normalizer.py -v
collected 10 items

tests/test_normalizer.py::test_base64_encoded_card_number_is_found PASSED
tests/test_normalizer.py::test_short_base64_looking_string_is_ignored PASSED
tests/test_normalizer.py::test_url_encoding_reveals_hidden_card_number PASSED
tests/test_normalizer.py::test_json_embedded_card_number_is_found PASSED
tests/test_normalizer.py::test_gzip_compressed_card_number_is_found PASSED
tests/test_normalizer.py::test_clean_text_produces_no_obfuscation_results PASSED
tests/test_normalizer.py::test_nested_base64_in_json_is_recursively_unwrapped PASSED
tests/test_normalizer.py::test_url_decode_returns_none_when_nothing_encoded PASSED
tests/test_normalizer.py::test_json_extract_returns_empty_for_non_json_text PASSED
tests/test_normalizer.py::test_decompress_returns_none_for_non_compressed_bytes PASSED

============================== 10 passed in 0.15s ==============================
```

### A real bug this test suite caught before delivery

`test_nested_base64_in_json_is_recursively_unwrapped` failed on its first
run during development of this project — worth documenting exactly why,
since it's a good example of why the threshold logic needed a second look
rather than a quick patch:

The test base64-encodes a short card-number string, producing a token
ending in `==` padding. The original `try_decode_base64()` applied its
`min_run_length` (40) check **only to the non-padding alphabet-character
run**, via a regex quantifier `[A-Za-z0-9+/]{40,}={0,2}`. A 40-character
total token ending in `==` only has **38** non-padding characters —
one character short of the 40-character floor — so the regex silently
failed to match, and the recursive unwrap never happened.

The fix: capture the token first with a low technical floor
(`{4,}`, just enough to be one valid base64 group), *then* filter by
`len(candidate) >= min_run_length` against the **total** captured length
(letters plus padding). This is implemented in
`try_decode_base64()` above — see its docstring, which documents this
exact reasoning inline, not just in this doc, so a future editor hits the
explanation at the point they'd be tempted to reintroduce the same bug.

This is included here deliberately: "wrote tests, all passed the first time"
would be a less credible engineering story than "wrote tests, one failed,
here's the root cause and the fix."

## ✅ Expected Result

Real output from the interactive command in 💻 Commands above:
```
base64 True 1 ['card_detector']
```
And from the full pipeline demo (`docs/TELEMETRY.md`), a base64-encoded
private key was correctly flagged even though it produced **zero** direct
Phase 4 matches:
```
[ALERT] file:file_modified -> simulations/monitored/obfuscated_note.txt
        categories=['obfuscated:base64']
        needs_ai_review=False  (Phase 6 will act on this flag)
```
(`needs_ai_review` is `False` here because `run_pipeline_demo.py`'s
`analyze_event()` only feeds *direct* detection results into
`summarize()` — the obfuscation-layer match is surfaced separately as
`categories=['obfuscated:base64']`. Whether an AI-review flag should also
consider obfuscation-layer matches is exactly the kind of wiring decision
Phase 6/7 will need to make explicitly, not by accident; noted here as a
forward pointer, not resolved in this phase.)

## 🔧 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| A base64-encoded secret isn't found | Encoded token is shorter than `min_base64_run_length` (40) total characters | Expected for short payloads — lower the threshold in `config/detection_policy.yaml` if your use case needs to catch shorter encoded runs, understanding this raises false-positive risk on incidental base64-looking text |
| `normalize_and_rescan()` seems to hang or run long on a large document | Many incidental base64-looking substrings in the document, each attempted | Not infinite — bounded by `max_recursion_depth` — but can be slow on large inputs with lots of near-miss candidates; for Phase 3's real collectors this is naturally bounded by the `excerpt_max_chars` cap (4000 chars) already applied before content reaches this layer |
| JSON extraction finds nothing in a document that clearly contains `{...}` | The braces aren't valid JSON (e.g. Python dict repr with single quotes) | `try_extract_json_strings()` uses strict `json.loads`, not a permissive parser — this is deliberate, to avoid false "decodes" on text that merely looks JSON-ish |
| Gzip/zip detection doesn't fire on a `.gz` file | You passed `text` (str) instead of `bytes` — compression is inherently binary | Read the file with `path.read_bytes()`, not `read_text()`, before calling `normalize_and_rescan()` |

## 🔐 Security Considerations

- Recursion depth is bounded (`max_recursion_depth`) specifically to prevent
  resource-exhaustion from adversarial or corrupt nested-encoding input —
  the same defensive posture as guarding against decompression bombs,
  applied here at a much smaller scale appropriate to this project.
- Decoded content is rescanned through the *same* Phase 4 detectors that
  already never leak raw secrets/PANs — the safety property established in
  Phase 4 carries through automatically here, because this layer calls
  Phase 4 rather than reimplementing any detection logic.

## 📌 Completion Criteria

- [x] Base64, URL-encoding, JSON-embedding, and gzip/zip detection all
      implemented and independently tested (10 tests)
- [x] Recursive nested-encoding case tested and passing (JSON containing
      base64 containing a card number)
- [x] A real bug (padding/threshold interaction) found, root-caused, fixed,
      and documented rather than silently patched
- [x] DR6 (Phase 0) satisfied and cross-referenced to passing tests
- [ ] You have run the interactive command above with your own payload (not
      the one in this doc) and confirmed it's caught
