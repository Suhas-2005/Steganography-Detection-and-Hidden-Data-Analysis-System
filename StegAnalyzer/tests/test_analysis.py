"""
Tests for modules/binwalk_analyzer.py, steghide_analyzer.py, history_manager.py, and report_generator.py.
"""

from pathlib import Path
import tempfile
import pytest

from modules.binwalk_analyzer import parse_binwalk_output, analyze_embedded
from modules.steghide_analyzer import is_format_supported, get_format_explanation, inspect_file, extract_data
from modules.history_manager import (
    init_db,
    add_investigation,
    get_all_investigations,
    get_investigation_by_id,
    get_session_statistics,
    clear_all_history,
)
from modules.report_generator import generate_forensic_report


def test_binwalk_output_parser():
    sample_raw = """
DECIMAL       HEXADECIMAL     DESCRIPTION
-------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
24500         0x5FB4          Zip archive data, at least v2.0 to extract
"""
    parsed = parse_binwalk_output(sample_raw)
    assert len(parsed) == 2
    assert parsed[0]["offset_dec"] == 0
    assert parsed[0]["offset_hex"] == "0x0"
    assert "JPEG" in parsed[0]["description"]
    assert parsed[1]["offset_dec"] == 24500
    assert "Zip" in parsed[1]["description"]


def test_steghide_carrier_format_support():
    # JPEG and BMP are supported
    assert is_format_supported(Path("evidence.jpg")) is True
    assert is_format_supported(Path("evidence.jpeg")) is True
    assert is_format_supported(Path("evidence.bmp")) is True
    assert is_format_supported(Path("EVIDENCE.JPG")) is True

    # PNG is STRICTLY UNSUPPORTED by Steghide
    assert is_format_supported(Path("evidence.png")) is False
    assert is_format_supported(Path("evidence.gif")) is False

    png_explanation = get_format_explanation(".png")
    assert "NOT supported by Steghide" in png_explanation


def test_steghide_unsupported_format_guard():
    # Calling inspect_file on a PNG must reject without calling the binary
    res = inspect_file(Path("photo.png"))
    assert res["success"] is False
    assert res["format_supported"] is False
    assert "unsupported by Steghide" in res["error"]


def test_history_manager_crud():
    init_db()
    clear_all_history()

    test_record = {
        "investigation_id": "TEST-INV-001",
        "timestamp": "2026-10-31 12:00:00 UTC",
        "filename": "suspicious.jpg",
        "file_type": "JPEG",
        "file_size_str": "1.2 MB",
        "dimensions": "1920x1080 px",
        "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "status": "Potential indicator identified",
        "findings_summary": "Appended zip data detected.",
        "full_results": {"test": "data"},
    }

    add_investigation(test_record)

    all_records = get_all_investigations()
    assert len(all_records) >= 1
    assert any(r["investigation_id"] == "TEST-INV-001" for r in all_records)

    single = get_investigation_by_id("TEST-INV-001")
    assert single is not None
    assert single["filename"] == "suspicious.jpg"

    stats = get_session_statistics([test_record])
    assert stats["total_analyzed"] == 1
    assert stats["suspicious_count"] == 1
    assert stats["extracted_count"] == 0

    clear_all_history()
    assert len(get_all_investigations()) == 0


def test_pdf_report_generation():
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        sample_analysis = {
            "investigation_id": "INV-UNITTEST",
            "timestamp": "2026-10-31 16:30:00 UTC",
            "filename": "test_image.jpg",
            "file_format": "JPEG",
            "file_size_str": "245.2 KB",
            "dimensions": "800 × 600 px",
            "color_mode": "RGB",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "overall_status": "No known indicator reported",
            "overall_summary": "Examination concluded with no anomalies detected.",
            "metadata_results": {
                "tool_available": True,
                "metadata": {"Make": "Canon", "Model": "EOS 80D"},
                "key_findings": {"Camera Info": {"Make": "Canon", "Model": "EOS 80D"}},
            },
            "binwalk_results": {
                "tool_available": True,
                "summary": "Standard JPEG markers only.",
                "signatures": [{"offset_dec": 0, "offset_hex": "0x0", "description": "JPEG image data"}],
            },
            "steghide_results": {
                "format_supported": True,
                "tool_available": True,
                "explanation": "No embedded content detected with empty passphrase.",
                "capacity": "15.4 KB",
            },
            "extraction_results": {},
            "tools_status": {
                "exiftool": {"available": True, "version": "12.70"},
                "binwalk": {"available": False, "version": None},
                "steghide": {"available": True, "version": "0.5.1"},
            },
        }

        generated = generate_forensic_report(sample_analysis, output_path=tmp_path)
        assert generated.exists()
        assert generated.stat().st_size > 1000  # valid PDF generated
    finally:
        tmp_path.unlink(missing_ok=True)

