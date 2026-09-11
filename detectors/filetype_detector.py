"""
detectors/filetype_detector.py  (Phase 4.6)

Two-layer file type detection:
  1. Extension lookup against config/detection_policy.yaml's
     `sensitive_file_types` map (fast, primary signal).
  2. Magic-byte sniffing on the first few bytes of content, used as a
     corroborating signal and to catch the common evasion of simply
     renaming a file's extension (e.g. secrets.pem renamed to notes.txt
     still starts with "-----BEGIN"; a renamed .zip/.xlsx/.docx still
     starts with the "PK\x03\x04" ZIP local file header, since OOXML and
     modern Office formats ARE zip archives).

This module reports both the extension-based verdict and a
`extension_mismatch` flag when the two layers disagree, since that mismatch
is itself a mild insider-threat signal worth surfacing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from common.event_schema import DetectionResult

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "detection_policy.yaml"

# (label, byte signature, offset)
_MAGIC_SIGNATURES: list[tuple[str, bytes, int]] = [
    ("zip_or_office_ooxml", b"PK\x03\x04", 0),   # .zip, .docx, .xlsx, .pptx (all OOXML) share this
    ("gzip", b"\x1f\x8b", 0),
    ("pdf", b"%PDF-", 0),
    ("sqlite3_db", b"SQLite format 3\x00", 0),
    ("pem_private_key", b"-----BEGIN", 0),
    ("rar", b"Rar!\x1a\x07", 0),
    ("elf_binary", b"\x7fELF", 0),
    ("windows_pe_exe", b"MZ", 0),
]


def load_sensitive_types(policy_path: str | Path = DEFAULT_POLICY_PATH) -> dict[str, Any]:
    with open(policy_path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    return policy.get("sensitive_file_types", {})


def _extension_lookup(extension: str, sensitive_types: dict[str, Any]) -> tuple[str | None, float]:
    ext = extension.lower()
    for group, spec in sensitive_types.items():
        if ext in [e.lower() for e in spec.get("extensions", [])]:
            return group, float(spec.get("risk_weight", 0.3))
    return None, 0.0


def sniff_magic_bytes(content_bytes: bytes) -> str | None:
    for label, sig, offset in _MAGIC_SIGNATURES:
        window = content_bytes[offset: offset + len(sig)]
        if window == sig:
            return label
    return None


def _extension_family_for_magic(magic_label: str | None) -> set[str]:
    """Which extensions we'd 'expect' for a given magic-byte label, for mismatch detection."""
    mapping = {
        "zip_or_office_ooxml": {".zip", ".docx", ".xlsx", ".pptx"},
        "gzip": {".gz", ".tgz"},
        "pdf": {".pdf"},
        "sqlite3_db": {".db", ".sqlite"},
        "pem_private_key": {".pem", ".key"},
        "rar": {".rar"},
    }
    return mapping.get(magic_label, set())


def detect(
    filename: str,
    content_bytes: bytes = b"",
    policy_path: str | Path = DEFAULT_POLICY_PATH,
) -> DetectionResult:
    sensitive_types = load_sensitive_types(policy_path)
    extension = Path(filename).suffix
    group, risk_weight = _extension_lookup(extension, sensitive_types)

    magic_label = sniff_magic_bytes(content_bytes) if content_bytes else None
    expected_exts = _extension_family_for_magic(magic_label)
    extension_mismatch = bool(magic_label) and bool(expected_exts) and extension.lower() not in expected_exts

    matched = bool(group) or extension_mismatch
    confidence = risk_weight
    if extension_mismatch:
        confidence = max(confidence, 0.65)  # renamed-extension evasion is itself notable

    category = group or ("extension_mismatch" if extension_mismatch else None)

    return DetectionResult(
        detector="filetype_detector",
        matched=matched,
        category=category,
        confidence=confidence,
        matches=[extension] if group else [],
        details={
            "extension": extension,
            "sensitive_group": group,
            "magic_byte_label": magic_label,
            "extension_mismatch": extension_mismatch,
        },
    )
