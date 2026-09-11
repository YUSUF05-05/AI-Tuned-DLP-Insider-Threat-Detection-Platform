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
