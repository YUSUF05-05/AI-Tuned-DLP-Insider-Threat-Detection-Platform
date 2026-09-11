import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detectors.keyword_detector import KeywordDetector, DEFAULT_POLICY_PATH  # noqa: E402


def test_policy_file_loads():
    detector = KeywordDetector()
    assert "customer_data" in detector.categories
    assert "financial" in detector.categories
    assert "credentials_context" not in detector.categories  # excluded by design


def test_matches_customer_data_category():
    detector = KeywordDetector()
    result = detector.detect("Attached is the full customer database export for Q3.")
    assert result.matched is True
    assert "customer_data" in result.details["categories_matched"]


def test_matches_financial_category():
    detector = KeywordDetector()
    result = detector.detect("Please confirm the wire transfer before end of day.")
    assert result.matched is True
    assert "financial" in result.details["categories_matched"]


def test_word_boundary_prevents_substring_false_positive():
    detector = KeywordDetector()
    # "ssn" must not match inside an unrelated word like "assignment"
    result = detector.detect("Your assignment is due tomorrow.")
    assert "customer_data" not in result.details.get("categories_matched", [])


def test_multi_word_phrase_matches_with_flexible_whitespace():
    detector = KeywordDetector()
    result = detector.detect("This is marked confidential and proprietary   material.")
    assert result.matched is True
    assert "source_code_markers" in result.details["categories_matched"]


def test_no_match_on_clean_text():
    detector = KeywordDetector()
    result = detector.detect("The weather this week has been mild and sunny.")
    assert result.matched is False
    assert result.matches == []


def test_multiple_categories_can_match_same_text():
    detector = KeywordDetector()
    text = "The board deck includes the customer database and payroll figures."
    result = detector.detect(text)
    matched_categories = set(result.details["categories_matched"])
    assert {"m_and_a_strategic", "customer_data", "financial"}.issubset(matched_categories)


def test_credentials_context_excluded_from_standalone_matching():
    detector = KeywordDetector()
    # "password" alone should NOT trigger keyword_detector, by policy design --
    # it exists only to corroborate secret_detector matches.
    result = detector.detect("Please reset your password using the portal.")
    assert result.matched is False
