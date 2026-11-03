"""
StegAnalyzer — Embedded file and signature analysis via Binwalk.

Executes Binwalk against an image to detect signatures, embedded archives,
or appended file structures. Results are categorized as potential forensic
indicators requiring further examination.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from utils.config import DEFAULT_TIMEOUT


def analyze_embedded(file_path: Path) -> dict[str, Any]:
    """Execute Binwalk against *file_path* to identify embedded signatures.

    Parameters
    ----------
    file_path : Path
        Path to the working copy of the image.

    Returns
    -------
    dict
        - success (bool)
        - tool_available (bool)
        - signatures (list of dicts: offset_dec, offset_hex, description)
        - signature_count (int)
        - has_suspicious_indicators (bool)
        - primary_format (str or None)
        - raw_output (str)
        - error (str or None)
        - summary (str)
    """
    binwalk_path = shutil.which("binwalk")
    if not binwalk_path:
        return {
            "success": False,
            "tool_available": False,
            "signatures": [],
            "signature_count": 0,
            "has_suspicious_indicators": False,
            "primary_format": None,
            "raw_output": "",
            "error": (
                "Binwalk is not installed or not found on the system PATH.\n\n"
                "Installation guides:\n"
                "• Windows: Binwalk can be installed via Python (`pip install binwalk`) "
                "or run in WSL / Kali Linux.\n"
                "• Kali Linux: sudo apt update && sudo apt install binwalk"
            ),
            "summary": "Tool unavailable: Binwalk is required for embedded signature analysis.",
        }

    try:
        # Run binwalk without shell=True for security
        proc = subprocess.run(
            [binwalk_path, str(file_path)],
            capture_output=True,
            text=True,
            timeout=DEFAULT_TIMEOUT,
        )
        raw_output = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
        signatures = parse_binwalk_output(proc.stdout)

        # Forensic indicator determination:
        # An image normally has its primary signature at offset 0.
        # Signatures starting later at non-zero offsets, or archive/executable signatures,
        # represent potential indicators.
        has_suspicious = False
        primary_format = None

        if signatures:
            first_sig = signatures[0]["description"].lower()
            primary_format = signatures[0]["description"]
            
            # Check for signatures beyond the primary header or suspicious payload types
            suspicious_keywords = [
                "zip archive", "gzip", "rar", "7-zip", "tar", "bzip2",
                "executable", "elf", "pe32", "dos executable", "pdf",
                "hidden", "compressed", "appended", "embedded"
            ]

            for idx, sig in enumerate(signatures):
                desc_lower = sig["description"].lower()
                # If signature is at a non-zero offset and matches known embedded types
                if sig.get("offset_dec", 0) > 0:
                    for kw in suspicious_keywords:
                        if kw in desc_lower:
                            has_suspicious = True
                            break
                elif idx > 0:
                    has_suspicious = True

        if signatures:
            if has_suspicious:
                summary = (
                    f"Identified {len(signatures)} signature(s). Potential indicator: "
                    f"Embedded or trailing signatures detected at non-zero offsets. "
                    f"Requires manual verification (not definitive proof of steganography)."
                )
            else:
                summary = (
                    f"Identified {len(signatures)} signature(s) corresponding to standard "
                    f"file header/metadata structures. No obvious anomalies detected."
                )
        else:
            summary = "No recognizable embedded file signatures reported by Binwalk."

        return {
            "success": True,
            "tool_available": True,
            "signatures": signatures,
            "signature_count": len(signatures),
            "has_suspicious_indicators": has_suspicious,
            "primary_format": primary_format,
            "raw_output": raw_output.strip(),
            "error": None,
            "summary": summary,
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "tool_available": True,
            "signatures": [],
            "signature_count": 0,
            "has_suspicious_indicators": False,
            "primary_format": None,
            "raw_output": "",
            "error": f"Binwalk scan timed out after {DEFAULT_TIMEOUT} seconds.",
            "summary": "Analysis timed out.",
        }
    except Exception as exc:
        return {
            "success": False,
            "tool_available": True,
            "signatures": [],
            "signature_count": 0,
            "has_suspicious_indicators": False,
            "primary_format": None,
            "raw_output": "",
            "error": f"Error executing Binwalk: {exc}",
            "summary": "Analysis failed due to an execution error.",
        }


def extract_embedded(file_path: Path, output_dir: Path) -> dict[str, Any]:
    """Perform controlled extraction of embedded files via Binwalk (-e).

    Extracted content is confined to *output_dir* and files are NEVER executed.

    Parameters
    ----------
    file_path : Path
        Working copy of the image.
    output_dir : Path
        Target extraction directory inside the project workspace.
    """
    binwalk_path = shutil.which("binwalk")
    if not binwalk_path:
        return {
            "success": False,
            "tool_available": False,
            "extracted_files": [],
            "raw_output": "",
            "error": "Binwalk is not installed or available.",
        }

    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Note: --matryoshka (-M) or -e creates an extraction folder.
        # We pass -C to direct extraction into output_dir
        proc = subprocess.run(
            [binwalk_path, "-e", "-C", str(output_dir), str(file_path)],
            capture_output=True,
            text=True,
            timeout=DEFAULT_TIMEOUT * 2,
        )

        extracted_files = []
        if output_dir.exists():
            for p in output_dir.rglob("*"):
                if p.is_file():
                    extracted_files.append(str(p))

        return {
            "success": proc.returncode == 0,
            "tool_available": True,
            "extracted_files": extracted_files,
            "raw_output": proc.stdout + proc.stderr,
            "error": None if proc.returncode == 0 else "Binwalk extraction finished with warnings or errors.",
        }
    except Exception as exc:
        return {
            "success": False,
            "tool_available": True,
            "extracted_files": [],
            "raw_output": "",
            "error": f"Extraction failed: {exc}",
        }


def parse_binwalk_output(raw_output: str) -> list[dict[str, Any]]:
    """Parse raw tabular Binwalk stdout into structured signature dictionaries.

    Standard Binwalk header:
    DECIMAL       HEXADECIMAL     DESCRIPTION
    -------------------------------------------------------------------------
    0             0x0             JPEG image data, JFIF standard 1.01
    1243          0x4DB           Zip archive data, ...
    """
    signatures: list[dict[str, Any]] = []
    lines = raw_output.splitlines()

    start_parsing = False
    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue

        # Look for the separator line following header
        if line_clean.startswith("---") or "DECIMAL" in line_clean:
            start_parsing = True
            continue

        if start_parsing:
            # Match decimal offset, hex offset, and description
            match = re.match(r"^(\d+)\s+(0x[0-9a-fA-F]+)\s+(.+)$", line_clean)
            if match:
                offset_dec = int(match.group(1))
                offset_hex = match.group(2)
                description = match.group(3).strip()
                signatures.append({
                    "offset_dec": offset_dec,
                    "offset_hex": offset_hex,
                    "description": description,
                })
            else:
                # Fallback for custom or multi-line formats
                parts = line_clean.split(None, 2)
                if len(parts) >= 3 and parts[0].isdigit():
                    try:
                        signatures.append({
                            "offset_dec": int(parts[0]),
                            "offset_hex": parts[1],
                            "description": parts[2].strip(),
                        })
                    except ValueError:
                        pass

    return signatures

