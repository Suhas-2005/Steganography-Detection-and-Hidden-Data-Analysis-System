"""
Tests for modules/metadata_analyzer.py.
"""

from pathlib import Path
import tempfile
import pytest

from modules.metadata_analyzer import (
    extract_metadata,
    parse_gps_coordinates,
    get_metadata_summary,
)


def test_missing_exiftool_handling():
    # Calling extract_metadata on any file when exiftool is not on PATH should return structured failure
    fake_path = Path("non_existent_image.jpg")
    result = extract_metadata(fake_path)
    assert isinstance(result, dict)
    assert "tool_available" in result
    assert "metadata" in result
    assert "key_findings" in result
    # If exiftool is not installed, tool_available must be False and error provided
    if not result["tool_available"]:
        assert result["success"] is False
        assert "ExifTool is not installed" in result["error"]


def test_parse_gps_coordinates():
    sample_meta = {
        "GPSLatitude": 37.7749,
        "GPSLongitude": -122.4194,
        "GPSAltitude": 15.5,
    }
    coords = parse_gps_coordinates(sample_meta)
    assert coords is not None
    assert coords["latitude"] == 37.7749
    assert coords["longitude"] == -122.4194
    assert "37.774900" in coords["formatted"]

    empty_coords = parse_gps_coordinates({})
    assert empty_coords is None


def test_get_metadata_summary():
    dummy_result = {
        "key_findings": {
            "GPS": {"GPSLatitude": 12.34},
            "Software": {"Software": "Adobe Photoshop 2024"},
        }
    }
    summary = get_metadata_summary(dummy_result)
    assert len(summary["flags"]) == 2
    assert any("GPS coordinates" in f for f in summary["flags"])
    assert any("Photoshop" in f for f in summary["flags"])

