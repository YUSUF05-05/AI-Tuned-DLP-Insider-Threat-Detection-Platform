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
