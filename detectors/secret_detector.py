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

def get_pattern(name: str) -> re.Pattern:
    for pattern_name, pattern, _ in _PATTERNS:
        if pattern_name == name:
            return pattern
    raise KeyError(name)


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


def detect(
    text: str,
    patterns: list[tuple[str, re.Pattern, float]] | None = None,
) -> DetectionResult:
    evidence: list[str] = []
    categories_found: set[str] = set()
    max_confidence = 0.0

    active_patterns = _PATTERNS if patterns is None else patterns

    for name, pattern, confidence in active_patterns:
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
