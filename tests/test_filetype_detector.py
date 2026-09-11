import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detectors.filetype_detector import detect, sniff_magic_bytes  # noqa: E402


def test_sensitive_extension_key_file():
    result = detect("id_rsa.key", content_bytes=b"")
    assert result.matched is True
    assert result.details["sensitive_group"] == "credentials_and_keys"
    assert result.confidence >= 0.9


def test_non_sensitive_extension():
    result = detect("notes.txt", content_bytes=b"just some plain text notes")
    assert result.details["sensitive_group"] is None
    assert result.details["extension_mismatch"] is False


def test_magic_byte_sniff_pdf():
    assert sniff_magic_bytes(b"%PDF-1.7 rest of file") == "pdf"


def test_magic_byte_sniff_zip_office():
    assert sniff_magic_bytes(b"PK\x03\x04restofzip") == "zip_or_office_ooxml"


def test_magic_byte_sniff_gzip():
    assert sniff_magic_bytes(b"\x1f\x8b\x08\x00restofgzip") == "gzip"


def test_extension_mismatch_flagged_when_renamed():
    # A PDF renamed to .txt -- extension says "not sensitive", magic bytes disagree.
    pdf_bytes = b"%PDF-1.4\n%fake pdf body for testing"
    result = detect("innocuous_notes.txt", content_bytes=pdf_bytes)
    assert result.details["extension_mismatch"] is True
    assert result.matched is True
    assert result.confidence >= 0.65


def test_no_mismatch_when_extension_and_magic_agree():
    pdf_bytes = b"%PDF-1.4\n%fake pdf body for testing"
    result = detect("report.pdf", content_bytes=pdf_bytes)
    assert result.details["extension_mismatch"] is False


def test_database_dump_extension():
    result = detect("prod_backup.sql")
    assert result.details["sensitive_group"] == "database_dumps"
