"""
ai/response_validator.py  (Phase 6)

Turns Ollama's raw message.content string into a common.event_schema.AIAnalysisResult.

Two separate concerns, deliberately not conflated:
  1. SHAPE validation -- is this valid JSON, are the required fields present,
     are they the right type.
  2. SEMANTIC consistency -- is this JSON self-contradictory (e.g. a real
     category with real confidence, but is_sensitive says otherwise). This
     is the part schema validation structurally cannot catch.

--------------------------------------------------------------------------
Three bugs fixed in this version (see docs / conversation for root cause):

1. ASYMMETRIC CONFIDENCE. The "is_sensitive=false but category suggests
   otherwise" branch capped confidence (CORRECTED_CONFIDENCE_CAP), but the
   reverse branch ("is_sensitive=true but category=none") left confidence
   untouched. Both branches now apply the same cap -- a self-contradictory
   response has demonstrated its confidence number isn't fully reliable
   regardless of which direction the contradiction runs.

2. EXECUTION ORDER. Unknown-category normalization used to run BEFORE
   reconciliation. That meant an unrecognized category (e.g. a model using
   "n/a" instead of the literal string "none") got rewritten to "other"
   first, and reconciliation then saw "other" -- a value that reads as "yes,
   a real category was assigned" -- and fired a correction that was never
   actually warranted. Reconciliation now runs FIRST, against the model's
   raw category string (so its own correction messages quote what the model
   actually said, not a value we invented), using a broader "is this a
   none-equivalent answer" check rather than an exact match on the literal
   string "none". Normalization into the closed KNOWN_CATEGORIES set happens
   LAST, purely for downstream storage/display, after consistency is settled.

3. STRING MISMATCH. KNOWN_CATEGORIES previously included an invented
   "swift_related" value that matches neither of swift_detector.py's real
   outputs ("swift_bic", "swift_payment_message"), so a genuine SWIFT
   finding could never be correlated between the deterministic and AI
   layers. Fixed to reuse the detectors' actual strings verbatim:
   payment_card, credential_secret, customer_data, financial,
   source_code_markers, m_and_a_strategic, swift_bic, swift_payment_message
   -- confirmed against card_detector.py, secret_detector.py,
   swift_detector.py, and detection_policy.yaml's keyword_categories keys.
   filetype_detector.py's categories (documents, archives,
   credentials_and_keys, database_dumps, source_code, extension_mismatch)
   are deliberately NOT included: those are file-TYPE classifications,
   already fully and deterministically solved by filetype_detector.py's
   extension/magic-byte logic. The AI reviews TEXT CONTENT for sensitivity;
   asking it to also re-derive file type would blur two different
   taxonomies and add nothing filetype_detector doesn't already provide.
--------------------------------------------------------------------------
"""

from __future__ import annotations

import json
from typing import Optional

from common.event_schema import AIAnalysisResult

# Reused verbatim from the deterministic detectors (see module docstring,
# bug #3) plus two AI-only meta-values ("other", "none") that no
# deterministic detector ever emits.
KNOWN_CATEGORIES = {
    "payment_card",           # detectors/card_detector.py
    "credential_secret",      # detectors/secret_detector.py
    "customer_data",          # detectors/keyword_detector.py (config/detection_policy.yaml key)
    "financial",              # detectors/keyword_detector.py (config/detection_policy.yaml key)
    "source_code_markers",    # detectors/keyword_detector.py (config/detection_policy.yaml key)
    "m_and_a_strategic",      # detectors/keyword_detector.py (config/detection_policy.yaml key)
    "swift_bic",              # detectors/swift_detector.py (bare-BIC, confidence 0.5)
    "swift_payment_message",  # detectors/swift_detector.py (MT structure, confidence 0.9)
    "other",                  # AI-only: doesn't fit any deterministic category
    "none",                   # AI-only: nothing sensitive found
}

# Strings a model might reasonably use to mean "no category applies" even
# though they aren't the literal enum value "none". Checked case-insensitively.
# This is what stops bug #2 from recurring under a different spelling.
_NONE_EQUIVALENTS = {"none", "n/a", "na", "not_applicable", "not applicable", "unknown", "null", ""}

# Below this confidence, a category-but-not-flagged-sensitive verdict is too
# weak a signal to override the model's own is_sensitive=False -- could
# genuinely be the model hedging on a borderline case, not contradicting itself.
INCONSISTENCY_CONFIDENCE_FLOOR = 0.3

# When a contradiction IS corrected -- either direction -- confidence is
# capped here rather than kept at face value. Applied symmetrically (fix #1).
CORRECTED_CONFIDENCE_CAP = 0.6

REQUIRED_FIELDS = ("is_sensitive", "category", "confidence", "reasoning")


def _is_none_equivalent(category: str) -> bool:
    return category.strip().lower() in _NONE_EQUIVALENTS


def validate(
    raw_content: str,
    model: Optional[str] = None,
    duration_ms: Optional[int] = None,
) -> AIAnalysisResult:
    """
    Parse and validate one Ollama /api/chat response's message.content string.
    Always returns an AIAnalysisResult -- never raises. status="error" with
    a specific `error` message on anything that couldn't be trusted.
    """
    try:
        parsed = json.loads(raw_content)
    except (json.JSONDecodeError, TypeError) as exc:
        return AIAnalysisResult(status="error", error=f"invalid JSON from model: {exc}",
                                 model=model, duration_ms=duration_ms)

    if not isinstance(parsed, dict):
        return AIAnalysisResult(status="error",
                                 error=f"expected a JSON object, got {type(parsed).__name__}",
                                 model=model, duration_ms=duration_ms)

    missing = [f for f in REQUIRED_FIELDS if f not in parsed]
    if missing:
        return AIAnalysisResult(status="error", error=f"missing required field(s): {missing}",
                                 model=model, duration_ms=duration_ms)

    is_sensitive = parsed["is_sensitive"]
    category = parsed["category"]
    confidence = parsed["confidence"]
    reasoning = parsed["reasoning"]

    if not isinstance(is_sensitive, bool):
        return AIAnalysisResult(status="error",
                                 error=f"is_sensitive must be a boolean, got {type(is_sensitive).__name__}",
                                 model=model, duration_ms=duration_ms)
    if not isinstance(category, str):
        return AIAnalysisResult(status="error",
                                 error=f"category must be a string, got {type(category).__name__}",
                                 model=model, duration_ms=duration_ms)
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
        return AIAnalysisResult(status="error",
                                 error=f"confidence must be a number, got {type(confidence).__name__}",
                                 model=model, duration_ms=duration_ms)
    if not isinstance(reasoning, str):
        return AIAnalysisResult(status="error",
                                 error=f"reasoning must be a string, got {type(reasoning).__name__}",
                                 model=model, duration_ms=duration_ms)

    # Clamp rather than reject -- an out-of-range confidence is a nuisance,
    # not evidence the whole response should be discarded.
    confidence = max(0.0, min(1.0, float(confidence)))

    # --- FIX #2: reconciliation runs on the RAW category, before normalization ---
    is_sensitive, category, confidence, reasoning = _reconcile_consistency(
        is_sensitive, category, confidence, reasoning
    )

    # Normalization into the closed set happens LAST, after consistency is
    # already resolved, so it can't manufacture a contradiction that wasn't
    # really there and can't erase the model's original wording from any
    # correction message logged above.
    if category not in KNOWN_CATEGORIES:
        reasoning = f"[category '{category}' not recognized, normalized to 'other'] {reasoning}"
        category = "other"

    return AIAnalysisResult(
        status="ok", is_sensitive=is_sensitive, category=category,
        confidence=confidence, reasoning=reasoning, model=model, duration_ms=duration_ms,
    )


def _reconcile_consistency(
    is_sensitive: bool, category: str, confidence: float, reasoning: str
) -> tuple[bool, str, float, str]:
    """
    Catches self-contradictory responses: a real category with real
    confidence, but is_sensitive says otherwise (or the reverse). Operates
    on whatever category string the model actually returned, including
    non-enum values -- see _is_none_equivalent() for why an exact match on
    the literal string "none" isn't enough (fix #2).
    """
    category_is_none_equivalent = _is_none_equivalent(category)

    # Model says NOT sensitive, but assigned a real-sounding category at
    # meaningful confidence -- contradiction. Correct is_sensitive, cap
    # confidence (fix #1: this cap also applies in the branch below).
    if not category_is_none_equivalent and confidence >= INCONSISTENCY_CONFIDENCE_FLOOR and not is_sensitive:
        corrected_confidence = min(confidence, CORRECTED_CONFIDENCE_CAP)
        reasoning = (
            f"[corrected: model reported is_sensitive=false but category='{category}' "
            f"confidence={confidence:.2f}, treating as sensitive] {reasoning}"
        )
        return True, category, corrected_confidence, reasoning

    # Reverse: model says IS sensitive but assigned no category -- also a
    # contradiction, and now capped the same way (fix #1).
    if is_sensitive and category_is_none_equivalent:
        corrected_confidence = min(confidence, CORRECTED_CONFIDENCE_CAP)
        reasoning = (
            f"[corrected: model reported is_sensitive=true with category='{category}' "
            f"(no real category), capping confidence] {reasoning}"
        )
        return is_sensitive, "other", corrected_confidence, reasoning

    return is_sensitive, category, confidence, reasoning
