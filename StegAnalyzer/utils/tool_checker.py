"""
StegAnalyzer — External-tool availability checker.

Detects whether ExifTool, Binwalk and Steghide are installed and
reports version information when available.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Optional

from utils.config import DEFAULT_TIMEOUT


def check_tool(tool_name: str) -> dict:
    """Check whether *tool_name* is available on the system PATH.

    Returns
    -------
    dict
        Keys: ``available`` (bool), ``version`` (str | None), ``path`` (str | None).
    """
    path: Optional[str] = shutil.which(tool_name)
    if not path:
        return {"available": False, "version": None, "path": None}

    version = _get_version(tool_name, path)
    return {"available": True, "version": version, "path": path}


def check_all_tools() -> dict[str, dict]:
    """Return availability info for every external tool."""
    return {name: check_tool(name) for name in ("exiftool", "binwalk", "steghide")}


# ── Version helpers ─────────────────────────────────────────────────────

def _get_version(tool_name: str, path: str) -> Optional[str]:
    """Try to extract a version string from the tool."""
    try:
        if tool_name == "exiftool":
            result = subprocess.run(
                [path, "-ver"],
                capture_output=True, text=True, timeout=DEFAULT_TIMEOUT,
            )
            return result.stdout.strip() if result.returncode == 0 else None

        if tool_name == "binwalk":
            # binwalk -h prints "Binwalk v<version>" on the first line
            result = subprocess.run(
                [path, "-h"],
                capture_output=True, text=True, timeout=DEFAULT_TIMEOUT,
            )
            for line in result.stdout.splitlines():
                if "binwalk" in line.lower() and "v" in line.lower():
                    return line.strip()
            return None

        if tool_name == "steghide":
            result = subprocess.run(
                [path, "--help"],
                capture_output=True, text=True, timeout=DEFAULT_TIMEOUT,
            )
            output = result.stdout or result.stderr
            for line in output.splitlines():
                if "steghide" in line.lower() and ("version" in line.lower() or "." in line):
                    return line.strip()
            return None

    except (subprocess.TimeoutExpired, OSError):
        pass
    return None
