import base64
import gzip
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from normalization.normalizer import (  # noqa: E402
    normalize_and_rescan,
    try_decode_base64,
    try_decode_url_encoding,
    try_extract_json_strings,
    try_decompress,
)
from detectors.engine import run_all  # noqa: E402

VALID_VISA = "4111111111111111"


def _any_card_match(obfuscation_results) -> bool:
    for ob in obfuscation_results:
        for det in ob.rescanned_detections:
            if det.detector == "card_detector" and det.matched:
                return True
    return False


def test_base64_encoded_card_number_is_found():
    secret_text = f"Customer card on file: {VALID_VISA}"
    encoded = base64.b64encode(secret_text.encode()).decode()
    carrier = f"Please process this payload: {encoded} and confirm."
    results = normalize_and_rescan(carrier, run_all)
    techniques = {r.technique for r in results}
    assert "base64" in techniques
    assert _any_card_match(results)


def test_short_base64_looking_string_is_ignored():
    # "SGVsbG8=" decodes to "Hello" (a real, valid base64 string) but is far
    # shorter than the configured min_base64_run_length, so should be skipped
    # to avoid noisy false positives on short incidental matches.
    decoded = try_decode_base64("SGVsbG8=", min_run_length=40, min_printable_ratio=0.85)
    assert decoded == []


def test_url_encoding_reveals_hidden_card_number():
    raw = f"note=card is {VALID_VISA} please charge"
    from urllib.parse import quote
    encoded = quote(raw)
    results = normalize_and_rescan(encoded, run_all)
    techniques = {r.technique for r in results}
    assert "url_encoding" in techniques
    assert _any_card_match(results)


def test_json_embedded_card_number_is_found():
    payload = json.dumps({"note": f"card is {VALID_VISA}", "user": "alice"})
    results = normalize_and_rescan(payload, run_all)
    techniques = {r.technique for r in results}
    assert "json_embedded" in techniques
    assert _any_card_match(results)


def test_gzip_compressed_card_number_is_found():
    secret_text = f"Backup export contains card {VALID_VISA}"
    compressed = gzip.compress(secret_text.encode())
    results = normalize_and_rescan(compressed, run_all)
    techniques = {r.technique for r in results}
    assert "gzip_or_zip" in techniques
    assert _any_card_match(results)


def test_clean_text_produces_no_obfuscation_results():
    results = normalize_and_rescan("Just a normal sentence about lunch plans.", run_all)
    assert results == []


def test_nested_base64_in_json_is_recursively_unwrapped():
    # Layer 2 (innermost): base64 of the card text
    inner_b64 = base64.b64encode(f"card number {VALID_VISA}".encode()).decode()
    # Layer 1: JSON document whose string value IS that base64 blob
    outer_json = json.dumps({"attachment_payload": inner_b64, "note": "see attached"})

    results = normalize_and_rescan(outer_json, run_all)
    techniques = {r.technique for r in results}
    assert "json_embedded" in techniques
    # The card number is only reachable after unwrapping JSON -> then base64,
    # i.e. a nested nested rescan; confirm it was actually found somewhere.
    assert _any_card_match(results)
    # At least one obfuscation result should report more than one unwrapped layer.
    assert any(r.layers >= 2 for r in results)


def test_url_decode_returns_none_when_nothing_encoded():
    assert try_decode_url_encoding("plain text, nothing to decode here") is None


def test_json_extract_returns_empty_for_non_json_text():
    assert try_extract_json_strings("this is not json at all") == []


def test_decompress_returns_none_for_non_compressed_bytes():
    assert try_decompress(b"just some plain ascii bytes, not compressed", 0.85) is None
