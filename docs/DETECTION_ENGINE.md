# PHASE 4 — DETERMINISTIC DETECTION ENGINE

## 🎯 Objective

Given a piece of text (and, where relevant, a filename/bytes), decide
whether it contains payment card data, SWIFT/payment-message structure,
credentials/secrets, policy-defined sensitive keywords, or a sensitive file
type — deterministically, with no AI/LLM involved, satisfying threat-model
requirements DR1-DR5 (`docs/THREAT_MODEL.md`).

## 🧠 Concept

Five independent detectors, one aggregator. Each detector is a pure function
(or a small stateless-per-call class) that takes text/bytes and returns a
`DetectionResult` (Phase 2's schema) — none of them know about each other,
none of them know about collectors, and none of them touch a database. This
is deliberate: it's what makes 44 of this project's 79 tests possible
without any I/O beyond one YAML file read.

**Confidence, not just true/false.** Every result carries a 0.0-1.0
confidence. A validated, Luhn-passing card number is 1.0 (deterministic,
high-precision). A bare SWIFT/BIC code with no surrounding message structure
is only 0.5 (format-only evidence, genuinely ambiguous — see "Known
Limitations" below for a concrete case where this distinction matters). This
matters because Phase 7's risk scoring (later) needs more than a boolean to
blend deterministic and AI signals sensibly, and Phase 4 is what has to
produce that number honestly.

**A DLP tool must not leak what it finds.** `secret_detector.py` never
writes a matched secret's raw value anywhere — every match becomes an
irreversible fingerprint (`pattern-name:first4chars...sha256[:8]`).
`card_detector.py` masks to PCI-DSS 3.3/3.4 style (first 6, last 4, rest
masked). This was a decision made *during* Phase 0's threat modeling
("the tool's own output is a new asset"), not bolted on afterward.

**Policy-driven, not hardcoded.** `keyword_detector.py` and
`filetype_detector.py` both read `config/detection_policy.yaml` at
construction time rather than hardcoding lists in Python — because in any
real DLP deployment, what counts as "sensitive" is an org-specific,
frequently-revised policy decision, not a code change.

## 🏗️ Architecture

```
                     ┌──────────────────┐
   text, filename ──▶│ detectors.engine │──▶ list[DetectionResult]
                     │    .run_all()    │
                     └──────────────────┘
                        │    │    │    │    │
                        ▼    ▼    ▼    ▼    ▼
                     card  swift secret keyword filetype
                   detector detector detector detector detector
                                              ▲
                                    config/detection_policy.yaml
```
`detectors.engine.needs_ai_review()` reduces the result list to a single
boolean using `AI_REVIEW_CONFIDENCE_THRESHOLD = 0.5` — this constant is
defined once, here, specifically so Phase 6/7 import it rather than each
redefining "what counts as ambiguous."

## 📁 Files

```
detectors/card_detector.py
detectors/swift_detector.py
detectors/secret_detector.py
detectors/keyword_detector.py
detectors/filetype_detector.py
detectors/engine.py
config/detection_policy.yaml          (shown in full in docs/ARCHITECTURE.md)
tests/test_card_detector.py
tests/test_swift_detector.py
tests/test_secret_detector.py
tests/test_keyword_detector.py
tests/test_filetype_detector.py
tests/test_engine.py
```

## ⚙️ Configuration

Detector-specific tuning from `config/detection_policy.yaml`:
```yaml
card_detection:
  accepted_lengths: [13, 14, 15, 16, 19]
  validate_with_luhn: true
swift_detection:
  bic_lengths: [8, 11]
  mt_field_tags: [":20:", ":32A:", ":50K:", ":50A:", ":52A:", ":57A:", ":59:", ":70:", ":71A:"]
```
Plus the full `keyword_categories` and `sensitive_file_types` maps (see
`docs/ARCHITECTURE.md` for the complete YAML).

## 💻 Commands

Run the whole detection layer's tests:
```powershell
python -m pytest tests/test_card_detector.py tests/test_swift_detector.py tests/test_secret_detector.py tests/test_keyword_detector.py tests/test_filetype_detector.py tests/test_engine.py -v
```

Try it interactively against one of the Phase 0-mapped synthetic fixtures:
```powershell
python simulations\verify_fixtures.py
```

Or against arbitrary text from the command line:
```powershell
python -c "from detectors.engine import run_all, summarize; print(summarize(run_all('Card on file: 4111111111111111')))"
```

## 🧩 Implementation

### `detectors/card_detector.py` — complete file
```python
"""
detectors/card_detector.py  (Phase 4.1)

Deterministic payment-card detector:
  1. Regex extracts digit-sequence candidates (allowing spaces/dashes as
     real-world card numbers are often written with separators).
  2. Each candidate is validated with the Luhn (mod 10) checksum algorithm.
  3. Candidates that pass Luhn are tagged with a best-guess brand using
     well-known IIN (Issuer Identification Number) prefix ranges.

Only candidates that pass BOTH the length filter and the Luhn checksum are
reported as matches — this keeps false positives low (a random 16-digit
number has roughly a 1-in-10 chance of passing Luhn by chance, which is why
Luhn alone is a weak *standalone* control in production DLP, but is a solid,
zero-cost pre-filter here; see docs/DETECTION_ENGINE.md "Known Limitations").
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from common.event_schema import DetectionResult

# Candidate extraction: 12-19 digits, optionally grouped with spaces or dashes.
_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,19}(?!\d)")


@dataclass
class CardMatch:
    raw: str                # original matched substring (not stored long-term)
    digits: str              # digits only
    brand: str
    masked: str               # e.g. "411111******1111" for safe logging


def luhn_is_valid(digits: str) -> bool:
    """
    Standard Luhn / mod-10 checksum.
    Starting from the rightmost digit, double every second digit; if the
    doubled value exceeds 9, subtract 9 (equivalent to summing its digits).
    The number is valid if the total sum is divisible by 10.
    """
    if not digits.isdigit():
        return False
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        d = int(ch)
        if i % 2 == 1:  # every second digit, 0-indexed from the right
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def identify_brand(digits: str) -> str:
    """Best-effort brand identification from IIN/BIN prefix ranges."""
    length = len(digits)
    if digits.startswith("4") and length in (13, 16, 19):
        return "visa"
    if length == 16 and (
        (digits[:2] in {str(n) for n in range(51, 56)})
        or (2221 <= int(digits[:4]) <= 2720)
    ):
        return "mastercard"
    if length == 15 and digits[:2] in {"34", "37"}:
        return "amex"
    if length == 16 and (
        digits.startswith("6011")
        or digits[:2] == "65"
        or (644 <= int(digits[:3]) <= 649)
    ):
        return "discover"
    return "unknown"


def mask(digits: str) -> str:
    """PCI-DSS-style masking: keep first 6 and last 4, mask the middle (Requirement 3.3)."""
    if len(digits) <= 10:
        return "*" * len(digits)
    return digits[:6] + "*" * (len(digits) - 10) + digits[-4:]


def find_card_candidates(text: str, accepted_lengths: list[int] | None = None) -> list[CardMatch]:
    """Extract and validate all card-like substrings in text."""
    accepted_lengths = accepted_lengths or [13, 14, 15, 16, 19]
    results: list[CardMatch] = []
    for m in _CANDIDATE_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if len(digits) not in accepted_lengths:
            continue
        if not luhn_is_valid(digits):
            continue
        results.append(CardMatch(raw=raw, digits=digits, brand=identify_brand(digits), masked=mask(digits)))
    return results


def detect(text: str, accepted_lengths: list[int] | None = None) -> DetectionResult:
    """
    Run the card detector over `text` and return a DetectionResult suitable
    for attaching to a DLPEvent. Never includes full unmasked PANs in the
    result — only masked forms are retained, in line with PCI-DSS 3.3/3.4.
    """
    matches = find_card_candidates(text, accepted_lengths=accepted_lengths)
    return DetectionResult(
        detector="card_detector",
        matched=len(matches) > 0,
        category="payment_card" if matches else None,
        confidence=1.0 if matches else 0.0,
        matches=[f"{m.brand}:{m.masked}" for m in matches],
        details={"count": len(matches), "brands": sorted({m.brand for m in matches})},
    )
```

### `detectors/swift_detector.py` — complete file
```python
"""
detectors/swift_detector.py  (Phase 4.2)

Detects two distinct SWIFT-related patterns, reported separately because
they indicate different things:

  1. BIC / SWIFT codes  — an 8 or 11-character identifier
     (4 letters bank code + 2 letters country code + 2 alphanumeric location
     code + optional 3 alphanumeric branch code). A bare BIC is weak evidence
     on its own (low confidence) since the format is short and can collide
     with unrelated strings.

  2. SWIFT MT-style message field tags (e.g. ":20:", ":32A:", ":59:") — these
     are structural markers from SWIFT MT (Message Type) payment messages
     (e.g. MT103 customer credit transfers). Seeing several of these tags
     together in one document is much stronger evidence of an actual
     payment-message excerpt than a bare BIC, so it is scored higher.

This module intentionally does NOT attempt full SWIFT MT parsing (field
validation, checksum blocks, etc.) — that is out of scope for a detection
pre-filter and would meaningfully increase false-negative risk if the parser
was too strict. See docs/DETECTION_ENGINE.md "Known Limitations".
"""

from __future__ import annotations

import re

from common.event_schema import DetectionResult

_BIC_RE = re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b")

# A short allowlist of country codes is NOT enforced here on purpose: BIC country
# codes cover essentially the full ISO 3166-1 alpha-2 list, so enforcing it would
# add maintenance burden for negligible precision gain. Confidence is instead
# raised by co-occurrence with MT field tags (see detect()).

DEFAULT_MT_FIELD_TAGS = [":20:", ":32A:", ":50K:", ":50A:", ":52A:", ":57A:", ":59:", ":70:", ":71A:"]


def find_bic_candidates(text: str) -> list[str]:
    return sorted(set(_BIC_RE.findall(text)))


def find_mt_field_tags(text: str, tags: list[str] | None = None) -> list[str]:
    tags = tags or DEFAULT_MT_FIELD_TAGS
    found = [t for t in tags if t in text]
    return found


def detect(text: str, mt_field_tags: list[str] | None = None) -> DetectionResult:
    bics = find_bic_candidates(text)
    mt_tags = find_mt_field_tags(text, tags=mt_field_tags)

    matched = bool(bics) or len(mt_tags) >= 2
    if not matched:
        return DetectionResult(detector="swift_detector", matched=False)

    # Confidence model:
    #   - MT tags present (>=2 distinct tags): strong structural evidence -> 0.9
    #   - Only a bare BIC, no MT structure: weaker evidence -> 0.5
    if len(mt_tags) >= 2:
        confidence = 0.9
        category = "swift_payment_message"
    else:
        confidence = 0.5
        category = "swift_bic"

    evidence = list(bics) + mt_tags
    return DetectionResult(
        detector="swift_detector",
        matched=True,
        category=category,
        confidence=confidence,
        matches=evidence,
        details={"bic_count": len(bics), "mt_tag_count": len(mt_tags)},
    )
```

### `detectors/secret_detector.py` — complete file
```python
"""
detectors/secret_detector.py  (Phase 4.3)

Detects common credential/secret formats: cloud provider keys, VCS/chat
platform tokens, private key material, JWTs, and generic API-key assignments.

IMPORTANT SECURITY DESIGN DECISION:
This detector NEVER writes the actual matched secret value into a
DetectionResult, log line, or event. A DLP tool that logs the very secrets
it finds — in cleartext, in its own audit trail — creates a second exposure
surface that is arguably worse than the original leak (the audit DB becomes
a target). Instead, every match is reduced to a stable, irreversible
fingerprint: `<pattern-name>:<first 4 chars>...<sha256[:8]>`. This is enough
for an analyst to confirm "yes, that's the same key we rotated last week"
without ever reconstructing the secret from the alert data.
"""

from __future__ import annotations

import hashlib
import re

from common.event_schema import DetectionResult

# (pattern_name, compiled_regex, base_confidence)
_PATTERNS: list[tuple[str, re.Pattern, float]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0.95),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"), 0.95),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 0.9),
    ("private_key_block", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"), 0.98),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"), 0.85),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9\-_.=]{20,}\b"), 0.6),
    ("generic_api_key_assignment", re.compile(
        r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?"), 0.55),
]

# AWS secret access keys are 40-char base64-ish strings with no fixed prefix,
# which collides with things like git commit hashes (40 HEX chars) and other
# incidental data. To keep false positives down, it is only flagged when it
# appears within CONTEXT_WINDOW characters of a contextual keyword.
_AWS_SECRET_CANDIDATE_RE = re.compile(r"\b[A-Za-z0-9/+=]{40}\b")
_AWS_CONTEXT_RE = re.compile(r"(?i)aws|secret[_-]?access[_-]?key")
CONTEXT_WINDOW = 60


def _fingerprint(pattern_name: str, matched_text: str) -> str:
    prefix = matched_text[:4]
    digest = hashlib.sha256(matched_text.encode("utf-8", errors="ignore")).hexdigest()[:8]
    return f"{pattern_name}:{prefix}...{digest}"


def _find_aws_secret_candidates(text: str) -> list[str]:
    hits = []
    for m in _AWS_SECRET_CANDIDATE_RE.finditer(text):
        start = max(0, m.start() - CONTEXT_WINDOW)
        end = min(len(text), m.end() + CONTEXT_WINDOW)
        window = text[start:end]
        if _AWS_CONTEXT_RE.search(window) and not re.fullmatch(r"[0-9a-f]{40}", m.group(0)):
            # exclude pure-hex 40-char strings -> almost always git SHA-1 hashes, not secrets
            hits.append(m.group(0))
    return hits


def detect(text: str) -> DetectionResult:
    evidence: list[str] = []
    categories_found: set[str] = set()
    max_confidence = 0.0

    for name, pattern, confidence in _PATTERNS:
        for m in pattern.finditer(text):
            evidence.append(_fingerprint(name, m.group(0)))
            categories_found.add(name)
            max_confidence = max(max_confidence, confidence)

    for secret in _find_aws_secret_candidates(text):
        evidence.append(_fingerprint("aws_secret_access_key", secret))
        categories_found.add("aws_secret_access_key")
        max_confidence = max(max_confidence, 0.7)

    matched = len(evidence) > 0
    return DetectionResult(
        detector="secret_detector",
        matched=matched,
        category="credential_secret" if matched else None,
        confidence=max_confidence,
        matches=evidence,  # fingerprints only, never raw secret values
        details={"pattern_types": sorted(categories_found), "count": len(evidence)},
    )
```

### `detectors/keyword_detector.py` — complete file
```python
"""
detectors/keyword_detector.py  (Phase 4.4)

Configurable, policy-driven keyword/category detector. Keyword lists live in
config/detection_policy.yaml (not hardcoded) so a security reviewer can tune
detection without touching code — this matters for a DLP tool specifically,
since keyword policy is expected to change per-organization in the real
world; hardcoding it would misrepresent how these tools are actually operated.

Matching rules:
  - Case-insensitive.
  - Whole-phrase matching with word boundaries, so "ssn" does not match
    inside an unrelated word like "assignment".
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from common.event_schema import DetectionResult

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "detection_policy.yaml"


def load_policy(policy_path: str | Path = DEFAULT_POLICY_PATH) -> dict[str, Any]:
    with open(policy_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _compile_category_patterns(categories: dict[str, Any]) -> dict[str, list[re.Pattern]]:
    compiled: dict[str, list[re.Pattern]] = {}
    for category, spec in categories.items():
        patterns = []
        for phrase in spec.get("keywords", []):
            # Escape the phrase, then allow flexible whitespace between words
            # (so "social security number" also matches "social  security number").
            escaped_words = [re.escape(w) for w in phrase.split()]
            pattern = r"\b" + r"\s+".join(escaped_words) + r"\b"
            compiled.setdefault(category, []).append(re.compile(pattern, re.IGNORECASE))
        compiled.setdefault(category, compiled.get(category, []))
    return compiled


class KeywordDetector:
    """
    Stateful wrapper so the YAML policy is parsed once (at construction) and
    reused across many detect() calls instead of re-reading/re-compiling
    regex on every event, which matters once this runs continuously against
    a live file/clipboard stream in Phase 3.
    """

    def __init__(self, policy_path: str | Path = DEFAULT_POLICY_PATH, exclude_categories: tuple[str, ...] = ("credentials_context",)):
        policy = load_policy(policy_path)
        categories = dict(policy.get("keyword_categories", {}))
        # credentials_context is intentionally excluded from standalone matching:
        # per the policy file's own description, it exists to raise confidence in
        # secret_detector matches, not to fire independently (it would otherwise
        # flag the word "password" appearing in ordinary IT documentation).
        for excluded in exclude_categories:
            categories.pop(excluded, None)
        self.categories = categories
        self._compiled = _compile_category_patterns(categories)

    def detect(self, text: str) -> DetectionResult:
        hits_by_category: dict[str, list[str]] = {}
        for category, patterns in self._compiled.items():
            for pattern in patterns:
                m = pattern.search(text)
                if m:
                    hits_by_category.setdefault(category, []).append(m.group(0).lower())

        matched = len(hits_by_category) > 0
        evidence = [f"{cat}:{phrase}" for cat, phrases in hits_by_category.items() for phrase in phrases]
        return DetectionResult(
            detector="keyword_detector",
            matched=matched,
            category=",".join(sorted(hits_by_category.keys())) if matched else None,
            confidence=0.6 if matched else 0.0,  # keywords alone are moderate-confidence, corroborating evidence
            matches=evidence,
            details={"categories_matched": sorted(hits_by_category.keys())},
        )
```

### `detectors/filetype_detector.py` — complete file
```python
"""
detectors/filetype_detector.py  (Phase 4.6)

Two-layer file type detection:
  1. Extension lookup against config/detection_policy.yaml's
     `sensitive_file_types` map (fast, primary signal).
  2. Magic-byte sniffing on the first few bytes of content, used as a
     corroborating signal and to catch the common evasion of simply
     renaming a file's extension (e.g. secrets.pem renamed to notes.txt
     still starts with "-----BEGIN"; a renamed .zip/.xlsx/.docx still
     starts with the "PK\x03\x04" ZIP local file header, since OOXML and
     modern Office formats ARE zip archives).

This module reports both the extension-based verdict and a
`extension_mismatch` flag when the two layers disagree, since that mismatch
is itself a mild insider-threat signal worth surfacing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from common.event_schema import DetectionResult

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "detection_policy.yaml"

# (label, byte signature, offset)
_MAGIC_SIGNATURES: list[tuple[str, bytes, int]] = [
    ("zip_or_office_ooxml", b"PK\x03\x04", 0),   # .zip, .docx, .xlsx, .pptx (all OOXML) share this
    ("gzip", b"\x1f\x8b", 0),
    ("pdf", b"%PDF-", 0),
    ("sqlite3_db", b"SQLite format 3\x00", 0),
    ("pem_private_key", b"-----BEGIN", 0),
    ("rar", b"Rar!\x1a\x07", 0),
    ("elf_binary", b"\x7fELF", 0),
    ("windows_pe_exe", b"MZ", 0),
]


def load_sensitive_types(policy_path: str | Path = DEFAULT_POLICY_PATH) -> dict[str, Any]:
    with open(policy_path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    return policy.get("sensitive_file_types", {})


def _extension_lookup(extension: str, sensitive_types: dict[str, Any]) -> tuple[str | None, float]:
    ext = extension.lower()
    for group, spec in sensitive_types.items():
        if ext in [e.lower() for e in spec.get("extensions", [])]:
            return group, float(spec.get("risk_weight", 0.3))
    return None, 0.0


def sniff_magic_bytes(content_bytes: bytes) -> str | None:
    for label, sig, offset in _MAGIC_SIGNATURES:
        window = content_bytes[offset: offset + len(sig)]
        if window == sig:
            return label
    return None


def _extension_family_for_magic(magic_label: str | None) -> set[str]:
    """Which extensions we'd 'expect' for a given magic-byte label, for mismatch detection."""
    mapping = {
        "zip_or_office_ooxml": {".zip", ".docx", ".xlsx", ".pptx"},
        "gzip": {".gz", ".tgz"},
        "pdf": {".pdf"},
        "sqlite3_db": {".db", ".sqlite"},
        "pem_private_key": {".pem", ".key"},
        "rar": {".rar"},
    }
    return mapping.get(magic_label, set())


def detect(
    filename: str,
    content_bytes: bytes = b"",
    policy_path: str | Path = DEFAULT_POLICY_PATH,
) -> DetectionResult:
    sensitive_types = load_sensitive_types(policy_path)
    extension = Path(filename).suffix
    group, risk_weight = _extension_lookup(extension, sensitive_types)

    magic_label = sniff_magic_bytes(content_bytes) if content_bytes else None
    expected_exts = _extension_family_for_magic(magic_label)
    extension_mismatch = bool(magic_label) and bool(expected_exts) and extension.lower() not in expected_exts

    matched = bool(group) or extension_mismatch
    confidence = risk_weight
    if extension_mismatch:
        confidence = max(confidence, 0.65)  # renamed-extension evasion is itself notable

    category = group or ("extension_mismatch" if extension_mismatch else None)

    return DetectionResult(
        detector="filetype_detector",
        matched=matched,
        category=category,
        confidence=confidence,
        matches=[extension] if group else [],
        details={
            "extension": extension,
            "sensitive_group": group,
            "magic_byte_label": magic_label,
            "extension_mismatch": extension_mismatch,
        },
    )
```

### `detectors/engine.py` — complete file (aggregator)
```python
"""
detectors/engine.py  (Phase 4 aggregator)

Runs every deterministic detector (card, SWIFT, secret, keyword, filetype)
against a piece of content and attaches the results to a DLPEvent.

This module is the seam where Phase 6 (AI/LLM analysis) will plug in later:
`run_all()` returns the deterministic verdicts; Phase 6 will take content
that scores above a "needs AI review" threshold (defined here, reused there)
and send ONLY that subset to the local LLM, rather than sending everything —
which is both a cost/latency optimization and a data-minimization choice
(least content leaves the deterministic layer necessary).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from common.event_schema import DetectionResult, DLPEvent
from detectors import card_detector, swift_detector, secret_detector, filetype_detector
from detectors.keyword_detector import KeywordDetector

# Any single deterministic detector at or above this confidence is enough to
# mark content as "needs AI review" once Phase 6 exists. Defined here so
# Phase 6/7 import ONE constant instead of redefining the threshold.
AI_REVIEW_CONFIDENCE_THRESHOLD = 0.5

_keyword_detector_singleton: Optional[KeywordDetector] = None


def _get_keyword_detector() -> KeywordDetector:
    global _keyword_detector_singleton
    if _keyword_detector_singleton is None:
        _keyword_detector_singleton = KeywordDetector()
    return _keyword_detector_singleton


def run_all(
    text: str,
    filename: Optional[str] = None,
    content_bytes: bytes = b"",
) -> list[DetectionResult]:
    """
    Run every applicable deterministic detector against `text`
    (and `content_bytes`/`filename` for the filetype detector, which needs
    the raw bytes and name rather than decoded text).
    """
    results: list[DetectionResult] = [
        card_detector.detect(text),
        swift_detector.detect(text),
        secret_detector.detect(text),
        _get_keyword_detector().detect(text),
    ]
    if filename is not None:
        results.append(filetype_detector.detect(filename, content_bytes=content_bytes))
    return results


def needs_ai_review(results: list[DetectionResult]) -> bool:
    """True if any deterministic detector's confidence meets the AI-review bar."""
    return any(r.matched and r.confidence >= AI_REVIEW_CONFIDENCE_THRESHOLD for r in results)


def enrich_event(
    event: DLPEvent,
    text: str,
    filename: Optional[str] = None,
    content_bytes: bytes = b"",
) -> DLPEvent:
    """Run all detectors and attach their results to the given event in place."""
    event.detections = run_all(text, filename=filename, content_bytes=content_bytes)
    return event


def summarize(results: list[DetectionResult]) -> dict:
    """Compact summary used by logging/CLI output and, later, the dashboard."""
    matched = [r for r in results if r.matched]
    return {
        "any_match": len(matched) > 0,
        "matched_detectors": [r.detector for r in matched],
        "categories": sorted({r.category for r in matched if r.category}),
        "max_confidence": max((r.confidence for r in matched), default=0.0),
        "needs_ai_review": needs_ai_review(results),
    }
```

## 🧪 Testing

Real, current output from this exact repository (not illustrative):

```
$ python -m pytest tests/test_card_detector.py tests/test_swift_detector.py tests/test_secret_detector.py tests/test_keyword_detector.py tests/test_filetype_detector.py tests/test_engine.py -v
collected 51 items

tests/test_card_detector.py::test_luhn_valid_numbers PASSED              [  1%]
tests/test_card_detector.py::test_masking_keeps_first6_last4_only PASSED [  9%]
...
tests/test_engine.py::test_summarize_clean_text_reports_no_match PASSED  [100%]

============================== 51 passed in 0.23s ==============================
```

| Test file | Count | Proves |
|---|---|---|
| `test_card_detector.py` | 10 | Luhn correctness against publicly-documented test card numbers, brand ID, PCI-style masking, PAN never appears unmasked in output |
| `test_swift_detector.py` | 7 | BIC extraction, MT field-tag detection, confidence split between bare-BIC and full-message-structure |
| `test_secret_detector.py` | 11 | AWS/GitHub/Slack/JWT/private-key/generic patterns; AWS secret's context-window gating; raw secrets never appear in `DetectionResult.matches` |
| `test_keyword_detector.py` | 8 | YAML policy loads; word-boundary correctness; multi-category matching; `credentials_context` correctly excluded from standalone firing |
| `test_filetype_detector.py` | 8 | Extension lookup; magic-byte sniffing; renamed-extension mismatch detection |
| `test_engine.py` | 7 | Aggregation across all five detectors; `needs_ai_review()` threshold behavior |

## ⚠️ Known Limitations (found through testing, not theoretical)

Documenting these honestly is itself a completion requirement — a detection
engine writeup that claims zero false positives is not credible.

**1. The bare-BIC pattern collides with ordinary all-caps English words of
the same length.** While building the synthetic test fixtures
(`simulations/synthetic_data/`), a document reading *"CONFIDENTIAL AND
PROPRIETARY -- INTERNAL USE ONLY"* triggered `swift_detector`, because
**"PROPRIETARY" is exactly 11 uppercase letters** — structurally
indistinguishable from a valid-format BIC to a character-class regex. Run
`python simulations/verify_fixtures.py` yourself to see it fire. This is
*why* the confidence split exists: a bare BIC scores only 0.5 (below the
"strong evidence" range), while an MT-message-structure match (multiple
field tags like `:20:`, `:32A:`) scores 0.9. The mitigation is architectural,
not a regex patch — a longer keyword blocklist would just chase the next
coincidental match.

**2. Luhn accepts degenerate sequences.** An all-zero digit string of valid
card length (e.g. sixteen `0`s) passes the Luhn checksum trivially (0 mod 10
= 0). This was caught while drafting a test fixture that happened to include
a placeholder token padded with zeros. Real card numbers are essentially
never all-zero, so this is low real-world impact, but it means Luhn alone is
a **filter, not proof** — exactly the caveat in `card_detector.py`'s own
docstring ("a random 16-digit number has roughly a 1-in-10 chance of passing
Luhn by chance").

**3. Keyword matching is exact-phrase, not semantic.** "social security
number" matches; a rephrasing like "the number tied to someone's social
security" does not. This is a precision/recall tradeoff made deliberately —
loosening it (fuzzy/stemmed matching) would raise false positives
significantly for a moderate recall gain, and is exactly the kind of gap
Phase 6's AI layer is meant to catch instead of pushing the regex to do
everything.

**4. The secret detector's generic patterns (`bearer_token`,
`generic_api_key_assignment`) are the lowest-confidence entries (0.55-0.6)
for a reason** — they're intentionally broad to catch secrets in formats not
covered by a named pattern, at the cost of being the most likely to false-positive
on non-secret data that merely looks like an assignment. `needs_ai_review()`'s
0.5 threshold means these still surface for review; they just shouldn't
dominate a risk score alone once Phase 7 exists.

## ✅ Expected Result

`python simulations/verify_fixtures.py` against the delivered synthetic
fixtures produces (real output):
```
sample_card_paste.txt
  direct categories:      ['payment_card']
  needs_ai_review:        True

sample_credential_leak.txt
  direct categories:      ['credential_secret']
  needs_ai_review:        True

sample_customer_export.csv
  direct categories:      ['customer_data', 'documents']
  needs_ai_review:        True

sample_obfuscated_payload_base64.txt
  direct categories:      (none)
  needs_ai_review:        False
  obfuscation techniques: ['base64']

sample_proprietary_source_note.txt
  direct categories:      ['source_code_markers', 'swift_bic']
  needs_ai_review:        True
```
(`sample_obfuscated_payload_base64.txt` correctly shows no *direct* match —
Phase 5's normalizer is what finds it. See `docs/NORMALIZATION.md`.)

## 🔧 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `yaml.scanner.ScannerError` when constructing `KeywordDetector()` | Malformed edit to `config/detection_policy.yaml` (usually inconsistent indentation) | YAML is whitespace-sensitive; validate with `python -c "import yaml; yaml.safe_load(open('config/detection_policy.yaml'))"` before assuming the code is at fault |
| A keyword category you added never fires | Forgot it needs `keywords:` as a YAML list, or added it under the wrong parent key | Compare indentation against an existing category in the file exactly |
| `card_detector` matches something you know isn't a card | Luhn-valid coincidental digit sequence (see Known Limitations #2) | Expected behavior, not a bug — this is inherent to Luhn-alone detection, which is why it's one signal among several, not a sole gate |
| `secret_detector` finds nothing in a file you know has a key | Your key format isn't one of the named patterns and doesn't match the generic fallback's `key/token/secret =` shape | Add a named pattern following the existing `_PATTERNS` list structure, with a test, rather than loosening the generic fallback (which would raise false positives project-wide) |

## 🔐 Security Considerations

- Every detector was designed so that **the evidence it returns cannot
  reconstruct the sensitive value** — masked PANs, fingerprinted secrets,
  matched-category-plus-lowercased-phrase for keywords (never the
  surrounding sensitive sentence). This matters because `DetectionResult`
  objects are what eventually get persisted (Phase 9) and displayed
  (Phase 10) — the safety property has to hold at the source.
- `AI_REVIEW_CONFIDENCE_THRESHOLD = 0.5` (in `detectors/engine.py`) is a
  single, named constant specifically so Phase 6/7 can't accidentally drift
  from Phase 4's definition of "ambiguous enough to need a second opinion."

## 📌 Completion Criteria

- [x] All five detectors implemented and independently tested (44 tests)
- [x] Aggregator (`engine.py`) implemented and tested (7 tests) — 51 total
- [x] DR1-DR5 (Phase 0) each traced to a passing test suite
- [x] Known limitations documented with concrete, reproduced examples (not
      hypothetical caveats)
- [x] No detector ever returns a raw secret/PAN/private key in its
      `DetectionResult` — verified by dedicated tests
      (`test_aws_access_key_never_appears_raw_in_evidence`,
      `test_masking_keeps_first6_last4_only`)
- [ ] You have run `python simulations/verify_fixtures.py` yourself and can
      explain *why* `sample_proprietary_source_note.txt` triggers
      `swift_detector` — if you can't, re-read "Known Limitations #1" above
      before moving to Phase 5
