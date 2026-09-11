"""
tests/test_card_detector.py (Phase 4.1 validation)

Uses only well-known, publicly documented SYNTHETIC test card numbers
(the same numbers Stripe/PayPal/sandbox payment processors publish for
integration testing). These are not real cardholder data — see
docs/DETECTION_ENGINE.md "Test Data Provenance".
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detectors.card_detector import luhn_is_valid, identify_brand, mask, find_card_candidates, detect

# Well-known public test numbers (Luhn-valid, brand-recognizable)
VALID_VISA = "4111111111111111"
VALID_VISA_2 = "4012888888881881"
VALID_MASTERCARD = "5555555555554444"
VALID_AMEX = "378282246310005"
VALID_DISCOVER = "6011111111111117"

# Deliberately Luhn-invalid (last digit tampered)
INVALID_VISA = "4111111111111112"
RANDOM_NON_CARD_NUMBER = "1234567890123"  # 13 digits, arbitrary, should fail Luhn


def test_luhn_valid_numbers():
    for num in [VALID_VISA, VALID_VISA_2, VALID_MASTERCARD, VALID_AMEX, VALID_DISCOVER]:
        assert luhn_is_valid(num), f"{num} expected to be Luhn-valid"


def test_luhn_rejects_tampered_number():
    assert not luhn_is_valid(INVALID_VISA)


def test_luhn_rejects_random_digits():
    assert not luhn_is_valid(RANDOM_NON_CARD_NUMBER)


def test_brand_identification():
    assert identify_brand(VALID_VISA) == "visa"
    assert identify_brand(VALID_MASTERCARD) == "mastercard"
    assert identify_brand(VALID_AMEX) == "amex"
    assert identify_brand(VALID_DISCOVER) == "discover"


def test_masking_keeps_first6_last4_only():
    masked = mask(VALID_VISA)
    assert masked.startswith("411111")
    assert masked.endswith("1111")
    assert "*" in masked
    assert VALID_VISA not in masked  # full PAN must never appear in masked output


def test_find_candidates_in_prose_with_separators():
    text = f"Please charge card 4111 1111 1111 1111 for the order, thanks."
    matches = find_card_candidates(text)
    assert len(matches) == 1
    assert matches[0].brand == "visa"


def test_find_candidates_ignores_non_luhn_numbers():
    text = f"Tracking number 1234567890123 was scanned at the warehouse."
    matches = find_card_candidates(text)
    assert len(matches) == 0


def test_detect_returns_matched_true_with_masked_evidence_only():
    text = f"card={VALID_VISA}"
    result = detect(text)
    assert result.matched is True
    assert result.category == "payment_card"
    assert result.confidence == 1.0
    assert all(VALID_VISA not in m for m in result.matches), "unmasked PAN leaked into DetectionResult"


def test_detect_no_match_on_clean_text():
    result = detect("This paragraph contains no payment data at all.")
    assert result.matched is False
    assert result.category is None


def test_detect_multiple_cards_multiple_brands():
    text = f"{VALID_VISA} and also {VALID_MASTERCARD}"
    result = detect(text)
    assert result.details["count"] == 2
    assert set(result.details["brands"]) == {"visa", "mastercard"}
