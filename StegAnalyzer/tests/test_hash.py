"""
Tests for modules/hash_generator.py.
"""

from pathlib import Path
import hashlib
import tempfile
import pytest

from modules.hash_generator import (
    calculate_sha256,
    calculate_sha256_from_bytes,
    verify_integrity,
)


def test_calculate_sha256_from_bytes():
    sample_data = b"StegAnalyzer Forensic Integrity Test Payload"
    expected = hashlib.sha256(sample_data).hexdigest()
    assert calculate_sha256_from_bytes(sample_data) == expected


def test_calculate_sha256_file():
    sample_data = b"Random binary evidence stream 1234567890" * 500
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(sample_data)
        tmp_path = Path(tmp.name)

    try:
        expected = hashlib.sha256(sample_data).hexdigest()
        assert calculate_sha256(tmp_path) == expected
        assert verify_integrity(tmp_path, expected) is True
        assert verify_integrity(tmp_path, "0" * 64) is False
    finally:
        tmp_path.unlink(missing_ok=True)

