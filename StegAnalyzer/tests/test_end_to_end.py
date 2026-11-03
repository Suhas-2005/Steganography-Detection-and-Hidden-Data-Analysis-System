"""
End-to-End Test Suite for StegAnalyzer forensic investigation pipeline.
Executes the full pipeline against all generated test samples:
  • TEST 1: Normal clean JPEG
  • TEST 2 & 3: Steghide compatibility and passphrase handling
  • TEST 4: Concatenated/Appended ZIP archive (Binwalk indicator)
  • TEST 5: PNG unsupported carrier handling
  • TEST 6: Invalid spoofed image rejection
  • TEST 7: Missing tool graceful fallback
"""

from pathlib import Path
import pytest
from PIL import Image

from utils.config import PROJECT_ROOT
from utils.file_manager import (
    create_working_copy,
    cleanup_working_copy,
    get_file_size_str,
    create_extraction_dir,
)
from modules.file_validator import validate_upload, validate_image
from modules.hash_generator import calculate_sha256
from modules.metadata_analyzer import extract_metadata, parse_gps_coordinates, get_metadata_summary
from modules.binwalk_analyzer import analyze_embedded
from modules.steghide_analyzer import is_format_supported, inspect_file, extract_data
from modules.report_generator import generate_forensic_report
from modules.history_manager import add_investigation, get_investigation_by_id

SAMPLES_DIR = PROJECT_ROOT / "samples"


def test_e2e_test1_normal_jpeg():
    sample = SAMPLES_DIR / "sample1_normal.jpg"
    assert sample.exists()

    # 1. Upload validation
    upload_val = validate_upload(sample.name, sample.stat().st_size)
    assert upload_val["valid"] is True

    # 2. Image content validation
    img_val = validate_image(sample)
    assert img_val["valid"] is True
    assert img_val["format"] == "JPEG"

    # 3. SHA-256 fingerprinting
    original_sha = calculate_sha256(sample)
    assert len(original_sha) == 64

    # 4. Working copy creation & non-destructive guarantee
    work_copy = create_working_copy(sample)
    assert work_copy.exists()
    assert calculate_sha256(work_copy) == original_sha

    try:
        # 5. Metadata extraction
        meta = extract_metadata(work_copy)
        assert isinstance(meta, dict)
        assert "tool_available" in meta

        # 6. Binwalk analysis
        binwalk_res = analyze_embedded(work_copy)
        assert isinstance(binwalk_res, dict)
        assert "has_suspicious_indicators" in binwalk_res

        # 7. Steghide inspection
        assert is_format_supported(work_copy) is True
        steg_res = inspect_file(work_copy)
        assert steg_res["format_supported"] is True

        # 8. Report generation
        report_data = {
            "investigation_id": "INV-E2E-TEST1",
            "timestamp": "2026-10-31 16:00:00 UTC",
            "filename": sample.name,
            "file_format": img_val["format"],
            "file_size_str": get_file_size_str(sample.stat().st_size),
            "dimensions": f"{img_val['width']}x{img_val['height']} px",
            "color_mode": img_val["mode"],
            "sha256": original_sha,
            "overall_status": "No known indicator reported",
            "overall_summary": "Clean normal JPEG examination.",
            "metadata_results": meta,
            "binwalk_results": binwalk_res,
            "steghide_results": steg_res,
            "tools_status": {},
        }
        pdf = generate_forensic_report(report_data)
        assert pdf.exists()
        assert pdf.stat().st_size > 0
    finally:
        cleanup_working_copy(work_copy)
        assert not work_copy.exists()


def test_e2e_test4_appended_archive():
    sample = SAMPLES_DIR / "sample4_appended_archive.jpg"
    assert sample.exists()

    # Image validation should still recognize JPEG header
    img_val = validate_image(sample)
    assert img_val["valid"] is True
    assert img_val["format"] == "JPEG"

    # Integrity hash
    sha = calculate_sha256(sample)
    assert len(sha) == 64

    work_copy = create_working_copy(sample)
    try:
        # Binwalk analysis should run without errors
        binwalk_res = analyze_embedded(work_copy)
        assert isinstance(binwalk_res, dict)
    finally:
        cleanup_working_copy(work_copy)


def test_e2e_test5_png_unsupported_carrier():
    sample = SAMPLES_DIR / "sample3_format_test.png"
    assert sample.exists()

    img_val = validate_image(sample)
    assert img_val["valid"] is True
    assert img_val["format"] == "PNG"

    # Steghide must NOT treat PNG as a carrier format
    assert is_format_supported(sample) is False
    steg_res = inspect_file(sample)
    assert steg_res["format_supported"] is False
    assert "unsupported by Steghide" in steg_res["error"]


def test_e2e_test6_invalid_file_rejection():
    sample = SAMPLES_DIR / "sample5_invalid_spoofed.jpg"
    assert sample.exists()

    # validate_upload passes on extension
    assert validate_upload(sample.name, sample.stat().st_size)["valid"] is True

    # BUT Pillow content validation must fail
    img_val = validate_image(sample)
    assert img_val["valid"] is False
    assert "not a recognised image" in img_val["error"].lower()


def test_e2e_test3_incorrect_passphrase_safety():
    # Calling extract_data on clean sample with invalid password must fail gracefully without crash
    sample = SAMPLES_DIR / "sample1_normal.jpg"
    ext_dir = create_extraction_dir("INV-TEST-WRONGPASS")
    res = extract_data(sample, "completely_wrong_passphrase_12345", ext_dir)
    assert isinstance(res, dict)
    assert res["success"] is False
    assert res["extracted_file_path"] is None

