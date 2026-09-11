import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detectors.swift_detector import find_bic_candidates, find_mt_field_tags, detect

SYNTHETIC_BIC = "TESTGB2LXXX"          # fictitious bank, clearly synthetic
SYNTHETIC_BIC_8 = "TESTUS33"


def test_finds_bic_candidates():
    text = f"Please wire funds using BIC {SYNTHETIC_BIC} for the settlement."
    found = find_bic_candidates(text)
    assert SYNTHETIC_BIC in found


def test_finds_8_char_bic():
    text = f"Beneficiary bank BIC: {SYNTHETIC_BIC_8}."
    found = find_bic_candidates(text)
    assert SYNTHETIC_BIC_8 in found


def test_finds_mt_field_tags():
    mt_message = (
        ":20:REF20260812TEST\n"
        ":32A:250812USD1000,00\n"
        ":50K:JOHN Q SAMPLE\n"
        ":59:JANE R SAMPLE\n"
    )
    tags = find_mt_field_tags(mt_message)
    assert ":20:" in tags
    assert ":32A:" in tags
    assert ":50K:" in tags
    assert ":59:" in tags
    assert len(tags) == 4


def test_detect_no_match_on_clean_prose():
    result = detect("This is an ordinary paragraph about quarterly planning.")
    assert result.matched is False


def test_detect_bare_bic_is_lower_confidence():
    text = f"Contact the branch, BIC {SYNTHETIC_BIC}, for details."
    result = detect(text)
    assert result.matched is True
    assert result.category == "swift_bic"
    assert result.confidence == 0.5


def test_detect_mt_structure_is_higher_confidence():
    mt_message = (
        ":20:REF20260812TEST\n"
        ":32A:250812USD1000,00\n"
        ":50K:JOHN Q SAMPLE\n"
        ":59:JANE R SAMPLE\n"
    )
    result = detect(mt_message)
    assert result.matched is True
    assert result.category == "swift_payment_message"
    assert result.confidence == 0.9
    assert result.details["mt_tag_count"] == 4


def test_detect_single_mt_tag_alone_is_not_matched():
    # A single field tag alone is common enough in unrelated text (e.g. ":59:" could
    # theoretically appear elsewhere) that it should NOT trigger on its own.
    text = "See note :59: for details."
    result = detect(text)
    assert result.matched is False
