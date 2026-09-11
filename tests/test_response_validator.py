import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ai.response_validator import validate, KNOWN_CATEGORIES  # noqa: E402

# The exact, verbatim response the live curl call against llama3.2:latest
# produced -- not a synthetic example.
REAL_INCONSISTENT_CONTENT = (
    '{\n  "is_sensitive": false,\n  "category": "payment_card",\n  "confidence": 0.8,\n'
    '  "reasoning": "The note contains a string of digits, which is a common format for a '
    'credit card number. The length of the number (16 digits) is also consistent with a '
    'standard credit card number. However, without more context or information, it is not '
    'possible to confirm with certainty that the note is a valid credit card number."\n}'
)


# --------------------------------------------------------------------
# Original cases (unaffected by the three fixes -- confirming no regressions)
# --------------------------------------------------------------------

def test_real_inconsistent_response_is_corrected():
    r = validate(REAL_INCONSISTENT_CONTENT, model="llama3.2:latest", duration_ms=11002)
    assert r.status == "ok"
    assert r.is_sensitive is True
    assert r.category == "payment_card"
    assert r.confidence == 0.6
    assert "[corrected:" in r.reasoning


def test_consistent_response_passes_through_unchanged():
    clean = '{"is_sensitive": true, "category": "credential_secret", "confidence": 0.95, "reasoning": "AWS key present"}'
    r = validate(clean)
    assert r.status == "ok"
    assert r.is_sensitive is True
    assert r.confidence == 0.95
    assert "[corrected" not in r.reasoning


def test_malformed_json_returns_error_status():
    r = validate("not json at all {{{")
    assert r.status == "error"
    assert "invalid JSON" in r.error


def test_missing_required_fields_returns_error_status():
    r = validate('{"is_sensitive": true, "category": "other"}')
    assert r.status == "error"
    assert "confidence" in r.error and "reasoning" in r.error


def test_out_of_range_confidence_is_clamped_not_rejected():
    r = validate('{"is_sensitive": true, "category": "other", "confidence": 1.7, "reasoning": "x"}')
    assert r.status == "ok"
    assert r.confidence == 1.0


def test_wrong_type_returns_error_status():
    r = validate('{"is_sensitive": "yes", "category": "other", "confidence": 0.5, "reasoning": "x"}')
    assert r.status == "error"
    assert "boolean" in r.error


def test_non_object_json_returns_error_status():
    r = validate('["not", "an", "object"]')
    assert r.status == "error"
    assert "expected a JSON object" in r.error


def test_below_confidence_floor_mismatch_not_corrected():
    r = validate('{"is_sensitive": false, "category": "financial", "confidence": 0.1, "reasoning": "weak signal"}')
    assert r.status == "ok"
    assert r.is_sensitive is False


# --------------------------------------------------------------------
# Bug #1 regression: ASYMMETRIC CONFIDENCE
# Both contradiction directions must cap confidence identically.
# --------------------------------------------------------------------

def test_bug1_forward_contradiction_caps_confidence():
    r = validate('{"is_sensitive": false, "category": "credential_secret", "confidence": 0.9, "reasoning": "x"}')
    assert r.is_sensitive is True
    assert r.confidence == 0.6  # capped, not 0.9


def test_bug1_reverse_contradiction_now_also_caps_confidence():
    # Before the fix: this branch left confidence untouched at 0.95.
    r = validate('{"is_sensitive": true, "category": "none", "confidence": 0.95, "reasoning": "x"}')
    assert r.status == "ok"
    assert r.category == "other"
    assert r.confidence == 0.6, f"expected symmetric cap at 0.6, got {r.confidence} (bug #1 regressed)"
    assert "[corrected:" in r.reasoning


# --------------------------------------------------------------------
# Bug #2 regression: EXECUTION ORDER
# An unrecognized-but-none-equivalent category (e.g. "n/a") must NOT be
# treated as a manufactured contradiction just because normalization used
# to run before reconciliation.
# --------------------------------------------------------------------

def test_bug2_none_equivalent_unrecognized_category_not_manufactured_as_contradiction():
    r = validate('{"is_sensitive": false, "category": "n/a", "confidence": 0.9, "reasoning": "nothing sensitive here"}')
    assert r.status == "ok"
    # Must NOT be flipped to True -- this was a consistent "nothing found"
    # response, just phrased differently than the literal enum value "none".
    assert r.is_sensitive is False, "bug #2 regressed: false contradiction was manufactured"
    assert r.confidence == 0.9, "confidence should be untouched -- no correction should have fired"
    assert r.category == "other"  # still normalized for storage, but AFTER consistency was resolved
    assert "not recognized" in r.reasoning
    assert "[corrected:" not in r.reasoning  # normalization note only, not a consistency correction


def test_bug2_genuinely_unrecognized_category_still_triggers_correction_with_accurate_message():
    # Contrast case: an unrecognized category that is NOT none-equivalent
    # should still correct (this was never the bug), and the message should
    # quote the model's actual raw category, not the post-normalization value.
    r = validate('{"is_sensitive": false, "category": "some_weird_label", "confidence": 0.8, "reasoning": "x"}')
    assert r.is_sensitive is True
    assert "some_weird_label" in r.reasoning  # raw value preserved in the correction message
    assert r.category == "other"  # normalized for storage after the fact


# --------------------------------------------------------------------
# Bug #3 regression: STRING MISMATCH
# KNOWN_CATEGORIES must contain the detectors' real strings, not invented ones.
# --------------------------------------------------------------------

def test_bug3_known_categories_matches_real_detector_strings():
    assert "swift_related" not in KNOWN_CATEGORIES, "old, non-matching invented value should be gone"
    assert "swift_bic" in KNOWN_CATEGORIES
    assert "swift_payment_message" in KNOWN_CATEGORIES
    assert "payment_card" in KNOWN_CATEGORIES
    assert "credential_secret" in KNOWN_CATEGORIES
    assert "customer_data" in KNOWN_CATEGORIES
    assert "financial" in KNOWN_CATEGORIES
    assert "source_code_markers" in KNOWN_CATEGORIES
    assert "m_and_a_strategic" in KNOWN_CATEGORIES
    # Deliberately excluded -- see module docstring: file-type categories
    # belong to filetype_detector.py, not to AI content classification.
    assert "documents" not in KNOWN_CATEGORIES
    assert "extension_mismatch" not in KNOWN_CATEGORIES


def test_bug3_swift_payment_message_recognized_without_normalization():
    r = validate('{"is_sensitive": true, "category": "swift_payment_message", "confidence": 0.85, "reasoning": "MT103 structure present"}')
    assert r.status == "ok"
    assert r.category == "swift_payment_message"
    assert "not recognized" not in r.reasoning  # must NOT be treated as unknown anymore
