"""
StegAnalyzer — Metadata extraction via ExifTool.

Wraps the ``exiftool`` CLI to extract EXIF / XMP / IPTC metadata from
image files and presents the results in structured form.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

from utils.config import DEFAULT_TIMEOUT

# Fields of special forensic interest
_KEY_FIELDS: dict[str, list[str]] = {
    "Basic Info": [
        "FileType", "FileTypeExtension", "MIMEType",
        "ImageWidth", "ImageHeight", "ImageSize",
        "BitDepth", "ColorSpace", "ColorType",
    ],
    "Camera Info": [
        "Make", "Model", "LensModel", "LensInfo",
        "FocalLength", "FNumber", "ExposureTime", "ISO",
    ],
    "Date / Time": [
        "DateTimeOriginal", "CreateDate", "ModifyDate",
        "FileModifyDate", "FileAccessDate",
    ],
    "GPS": [
        "GPSLatitude", "GPSLongitude", "GPSAltitude",
        "GPSLatitudeRef", "GPSLongitudeRef", "GPSPosition",
    ],
    "Software": [
        "Software", "HistorySoftwareAgent", "CreatorTool",
        "ProcessingSoftware",
    ],
}


def extract_metadata(file_path: Path) -> dict[str, Any]:
    """Run ExifTool on *file_path* and return parsed results.

    Returns
    -------
    dict
        Keys: ``success``, ``tool_available``, ``metadata``,
        ``key_findings``, ``raw_output``, ``error``.
    """
    exiftool_path = shutil.which("exiftool")
    if not exiftool_path:
        return {
            "success": False,
            "tool_available": False,
            "metadata": {},
            "key_findings": {},
            "raw_output": "",
            "error": (
                "ExifTool is not installed or not on the system PATH.\n\n"
                "• Windows: download from https://exiftool.org and add to PATH.\n"
                "• Kali Linux: sudo apt install libimage-exiftool-perl"
            ),
        }

    # ── JSON output ─────────────────────────────────────────────────
    try:
        result = subprocess.run(
            [exiftool_path, "-j", "-G", "-n", str(file_path)],
            capture_output=True,
            text=True,
            timeout=DEFAULT_TIMEOUT,
        )
        json_output = result.stdout
        metadata: dict = {}
        if json_output.strip():
            parsed = json.loads(json_output)
            if isinstance(parsed, list) and parsed:
                metadata = parsed[0]
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
        return {
            "success": False,
            "tool_available": True,
            "metadata": {},
            "key_findings": {},
            "raw_output": "",
            "error": f"ExifTool execution error: {exc}",
        }

    # ── Raw text output (for expandable view) ───────────────────────
    try:
        raw_result = subprocess.run(
            [exiftool_path, str(file_path)],
            capture_output=True,
            text=True,
            timeout=DEFAULT_TIMEOUT,
        )
        raw_output = raw_result.stdout
    except (subprocess.TimeoutExpired, OSError):
        raw_output = ""

    key_findings = _extract_key_findings(metadata)

    return {
        "success": True,
        "tool_available": True,
        "metadata": metadata,
        "key_findings": key_findings,
        "raw_output": raw_output,
        "error": None,
    }


def parse_gps_coordinates(metadata: dict) -> Optional[dict]:
    """Extract GPS coordinates from *metadata* if available."""
    lat = _find_value(metadata, "GPSLatitude")
    lon = _find_value(metadata, "GPSLongitude")

    if lat is not None and lon is not None:
        try:
            return {
                "latitude": float(lat),
                "longitude": float(lon),
                "altitude": _find_value(metadata, "GPSAltitude"),
                "formatted": f"{float(lat):.6f}, {float(lon):.6f}",
            }
        except (ValueError, TypeError):
            pass
    return None


def get_metadata_summary(metadata_result: dict) -> dict[str, Any]:
    """Categorise metadata into forensic-interest groups.

    Also flags notable observations (e.g. editing software detected,
    GPS coordinates present).
    """
    findings = metadata_result.get("key_findings", {})
    flags: list[str] = []

    if findings.get("GPS"):
        flags.append("📍 GPS coordinates are present in the image metadata.")
    software = findings.get("Software", {})
    if software:
        flags.append(
            f"🖥️ Editing / processing software detected: "
            f"{', '.join(str(v) for v in software.values() if v)}"
        )

    return {"categories": findings, "flags": flags}


# ── Internal helpers ────────────────────────────────────────────────────

def _extract_key_findings(metadata: dict) -> dict[str, dict[str, Any]]:
    """Map metadata keys into forensic-interest categories."""
    result: dict[str, dict[str, Any]] = {}
    for category, keys in _KEY_FIELDS.items():
        found: dict[str, Any] = {}
        for key in keys:
            value = _find_value(metadata, key)
            if value is not None:
                found[key] = value
        if found:
            result[category] = found
    return result


def _find_value(metadata: dict, key: str) -> Any:
    """Search for *key* in metadata values (ExifTool groups prefix keys)."""
    for meta_key, value in metadata.items():
        # ExifTool -G output uses "Group:Key" format
        if meta_key == key or meta_key.endswith(f":{key}"):
            return value
    return None

