"""
Tests for modules/file_validator.py.
"""

from pathlib import Path
import tempfile
import pytest
from PIL import Image

from modules.file_validator import validate_image, validate_upload
from utils.config import MAX_FILE_SIZE_BYTES


def test_validate_upload_allowed_extensions():
    assert validate_upload("evidence.jpg", 1024)["valid"] is True
    assert validate_upload("evidence.jpeg", 1024)["valid"] is True
    assert validate_upload("evidence.png", 1024)["valid"] is True
    assert validate_upload("evidence.bmp", 1024)["valid"] is True


def test_validate_upload_rejected_extensions():
    res = validate_upload("malicious.exe", 1024)
    assert res["valid"] is False
    assert "Unsupported extension" in res["error"]

    res_pdf = validate_upload("document.pdf", 1024)
    assert res_pdf["valid"] is False


def test_validate_upload_oversized():
    oversized = MAX_FILE_SIZE_BYTES + 1024
    res = validate_upload("huge_file.jpg", oversized)
    assert res["valid"] is False
    assert "exceeds" in res["error"]


def test_validate_image_genuine_jpeg():
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
        img = Image.new("RGB", (64, 64), color="blue")
        img.save(tmp.name, format="JPEG")
        tmp_path = Path(tmp.name)

    try:
        val = validate_image(tmp_path)
        assert val["valid"] is True
        assert val["format"] == "JPEG"
        assert val["width"] == 64
        assert val["height"] == 64
    finally:
        tmp_path.unlink(missing_ok=True)


def test_validate_image_genuine_png():
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        img = Image.new("RGBA", (32, 32), color="red")
        img.save(tmp.name, format="PNG")
        tmp_path = Path(tmp.name)

    try:
        val = validate_image(tmp_path)
        assert val["valid"] is True
        assert val["format"] == "PNG"
    finally:
        tmp_path.unlink(missing_ok=True)


def test_validate_image_spoofed_text_file():
    # TEST 6 requirement: text file renamed as .jpg
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
        tmp.write(b"This is just a text file masquerading as an image!")
        tmp_path = Path(tmp.name)

    try:
        val = validate_image(tmp_path)
        assert val["valid"] is False
        assert "not a recognised image" in val["error"].lower()
    finally:
        tmp_path.unlink(missing_ok=True)

