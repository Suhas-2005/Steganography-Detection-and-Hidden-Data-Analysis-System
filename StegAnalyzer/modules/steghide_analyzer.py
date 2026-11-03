"""
StegAnalyzer — Steganography inspection and extraction via Steghide.

Steghide is an open-source steganography program capable of hiding data
in various kinds of image and audio files. In digital forensics, it is used
to detect and extract hidden data from supported carrier formats.

Carrier Format Rules:
  • Supported: JPEG (.jpg, .jpeg) and BMP (.bmp)
  • Unsupported: PNG (.png) — PNG is not a supported Steghide carrier!
"""

from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

from utils.config import (
    DEFAULT_TIMEOUT,
    STEGHIDE_SUPPORTED_FORMATS,
)


def is_format_supported(file_path: Path) -> bool:
    """Return True if the file format is supported by Steghide (JPEG, BMP)."""
    return file_path.suffix.lower() in STEGHIDE_SUPPORTED_FORMATS


def get_format_explanation(extension: str) -> str:
    """Provide educational context regarding Steghide format compatibility."""
    ext = extension.lower()
    if ext in [".jpg", ".jpeg"]:
        return (
            "JPEG is a supported Steghide carrier. Steghide embeds data into "
            "the discrete cosine transform (DCT) coefficients of the JPEG image."
        )
    if ext == ".bmp":
        return (
            "BMP is a supported Steghide carrier. Steghide embeds data into "
            "the color sample values of the uncompressed bitmap."
        )
    if ext == ".png":
        return (
            "PNG is NOT supported by Steghide as a carrier format. "
            "While metadata extraction and file-structure analysis (Binwalk) can still be performed, "
            "Steghide inspection and extraction cannot be applied to PNG images."
        )
    return f"Format '{extension}' is not supported by Steghide."


def inspect_file(file_path: Path) -> dict[str, Any]:
    """Inspect *file_path* using Steghide info functionality.

    Parameters
    ----------
    file_path : Path
        Working copy of the image.

    Returns
    -------
    dict
        - success (bool)
        - tool_available (bool)
        - format_supported (bool)
        - embedded (bool or None)
        - capacity (str or None)
        - raw_output (str)
        - error (str or None)
        - explanation (str)
    """
    ext = file_path.suffix.lower()
    if not is_format_supported(file_path):
        return {
            "success": False,
            "tool_available": True,
            "format_supported": False,
            "embedded": None,
            "capacity": None,
            "raw_output": "",
            "error": f"Format '{ext}' is unsupported by Steghide (only JPEG and BMP are supported).",
            "explanation": get_format_explanation(ext),
        }

    steghide_path = shutil.which("steghide")
    if not steghide_path:
        return {
            "success": False,
            "tool_available": False,
            "format_supported": True,
            "embedded": None,
            "capacity": None,
            "raw_output": "",
            "error": (
                "Steghide is not installed or not found on the system PATH.\n\n"
                "Installation guides:\n"
                "• Windows: Download Steghide binary (steghide.sourceforge.net) and place in PATH.\n"
                "• Kali Linux: sudo apt update && sudo apt install steghide"
            ),
            "explanation": "Tool unavailable: Steghide is required for this module.",
        }

    try:
        # Running 'steghide info <file>' prompts for passphrase unless provided with -p ""
        # We test with an empty passphrase first to check general info and capacity
        proc = subprocess.run(
            [steghide_path, "info", str(file_path), "-p", ""],
            capture_output=True,
            text=True,
            timeout=DEFAULT_TIMEOUT,
        )

        raw_output = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
        raw_output_clean = raw_output.strip()

        # Parse capacity or embedded status
        capacity = None
        embedded_detected = False

        for line in raw_output.splitlines():
            line_str = line.strip()
            if "capacity:" in line_str.lower():
                parts = line_str.split(":", 1)
                if len(parts) > 1:
                    capacity = parts[1].strip()
            if "embedded file" in line_str.lower():
                embedded_detected = True

        if embedded_detected:
            explanation = (
                "Steghide reported potential embedded content or valid payload structure. "
                "Extraction can be attempted with a passphrase."
            )
        else:
            explanation = (
                "No embedded data detected with empty passphrase. Note: Steghide encrypts "
                "data by default; if a passphrase was used during embedding, data presence "
                "cannot be confirmed without supplying the valid passphrase. "
                "This negative result does NOT prove the absence of steganography."
            )

        return {
            "success": proc.returncode == 0 or "capacity" in raw_output.lower(),
            "tool_available": True,
            "format_supported": True,
            "embedded": embedded_detected,
            "capacity": capacity,
            "raw_output": raw_output_clean,
            "error": None if proc.returncode == 0 else "Steghide info reported non-zero status or passphrase required.",
            "explanation": explanation,
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "tool_available": True,
            "format_supported": True,
            "embedded": None,
            "capacity": None,
            "raw_output": "",
            "error": f"Steghide inspection timed out after {DEFAULT_TIMEOUT}s.",
            "explanation": "Command timed out.",
        }
    except Exception as exc:
        return {
            "success": False,
            "tool_available": True,
            "format_supported": True,
            "embedded": None,
            "capacity": None,
            "raw_output": "",
            "error": f"Error running Steghide: {exc}",
            "explanation": "Execution error during Steghide inspection.",
        }


def extract_data(file_path: Path, passphrase: str, output_dir: Path) -> dict[str, Any]:
    """Attempt Steghide extraction with a provided passphrase.

    Strict security controls:
      • No password cracking or brute-force attempts.
      • Output confined strictly to *output_dir*.
      • Extracted text files are safely decoded for preview.
      • Non-text files are saved for user download without execution.

    Parameters
    ----------
    file_path : Path
        Working copy of the image.
    passphrase : str
        User-supplied passphrase (may be empty string).
    output_dir : Path
        Controlled directory for extracted artifacts.

    Returns
    -------
    dict
        - success (bool)
        - tool_available (bool)
        - extracted_file_path (str or None)
        - extracted_file_name (str or None)
        - extracted_file_size (int or None)
        - extracted_text (str or None)
        - is_text (bool)
        - raw_output (str)
        - error (str or None)
        - message (str)
    """
    ext = file_path.suffix.lower()
    if not is_format_supported(file_path):
        return {
            "success": False,
            "tool_available": True,
            "extracted_file_path": None,
            "extracted_file_name": None,
            "extracted_file_size": None,
            "extracted_text": None,
            "is_text": False,
            "raw_output": "",
            "error": f"Format '{ext}' is unsupported by Steghide.",
            "message": get_format_explanation(ext),
        }

    steghide_path = shutil.which("steghide")
    if not steghide_path:
        return {
            "success": False,
            "tool_available": False,
            "extracted_file_path": None,
            "extracted_file_name": None,
            "extracted_file_size": None,
            "extracted_text": None,
            "is_text": False,
            "raw_output": "",
            "error": "Steghide is not installed or available.",
            "message": "Tool unavailable.",
        }

    output_dir.mkdir(parents=True, exist_ok=True)
    
    # We create a unique temporary target filename to avoid collision or path traversal
    temp_extract_name = f"extracted_payload_{uuid.uuid4().hex[:8]}"
    temp_extract_path = output_dir / temp_extract_name

    try:
        # Command: steghide extract -sf <file> -p <passphrase> -xf <outfile> -f
        # -f forces overwrite without prompt
        cmd = [
            steghide_path,
            "extract",
            "-sf", str(file_path),
            "-p", passphrase,
            "-xf", str(temp_extract_path),
            "-f"
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=DEFAULT_TIMEOUT,
        )

        raw_output = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
        raw_output_clean = raw_output.strip()

        # Check if the extracted file was created
        if temp_extract_path.exists() and temp_extract_path.stat().st_size > 0:
            file_size = temp_extract_path.stat().st_size
            
            # Determine if content is text or binary
            is_text = False
            extracted_text = None
            try:
                data = temp_extract_path.read_bytes()
                # Check for null bytes or attempt UTF-8 decode
                if b"\x00" not in data[:1024]:
                    text_candidate = data.decode("utf-8")
                    is_text = True
                    extracted_text = text_candidate
            except UnicodeDecodeError:
                is_text = False

            return {
                "success": True,
                "tool_available": True,
                "extracted_file_path": str(temp_extract_path),
                "extracted_file_name": temp_extract_name,
                "extracted_file_size": file_size,
                "extracted_text": extracted_text,
                "is_text": is_text,
                "raw_output": raw_output_clean,
                "error": None,
                "message": f"Successfully extracted hidden content ({file_size} bytes).",
            }
        else:
            # Extraction failed (wrong passphrase or no embedded data)
            error_msg = "Extraction unsuccessful. Either no hidden content exists or the passphrase is incorrect."
            if "could not extract" in raw_output_clean.lower() or "passphrase" in raw_output_clean.lower():
                error_msg = "Passphrase rejected or no compatible Steghide data found."

            return {
                "success": False,
                "tool_available": True,
                "extracted_file_path": None,
                "extracted_file_name": None,
                "extracted_file_size": None,
                "extracted_text": None,
                "is_text": False,
                "raw_output": raw_output_clean,
                "error": error_msg,
                "message": error_msg,
            }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "tool_available": True,
            "extracted_file_path": None,
            "extracted_file_name": None,
            "extracted_file_size": None,
            "extracted_text": None,
            "is_text": False,
            "raw_output": "",
            "error": "Extraction timed out.",
            "message": "The extraction operation timed out.",
        }
    except Exception as exc:
        return {
            "success": False,
            "tool_available": True,
            "extracted_file_path": None,
            "extracted_file_name": None,
            "extracted_file_size": None,
            "extracted_text": None,
            "is_text": False,
            "raw_output": "",
            "error": f"Extraction error: {exc}",
            "message": "An error occurred during extraction.",
        }

