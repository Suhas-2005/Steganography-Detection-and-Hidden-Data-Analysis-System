"""
StegAnalyzer — Image file validation.

Validates uploaded files using Pillow to detect the actual image format
rather than trusting the file extension.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PIL import Image, UnidentifiedImageError

from utils.config import SUPPORTED_IMAGE_FORMATS, MAX_FILE_SIZE_BYTES, MAX_FILE_SIZE_MB


def validate_upload(filename: str, size: int) -> dict[str, Any]:
    """Validate filename and size before saving.

    Returns
    -------
    dict
        ``valid``, ``filename``, ``size``, ``extension``, ``error``.
    """
    ext = Path(filename).suffix.lower()

    if size > MAX_FILE_SIZE_BYTES:
        return {
            "valid": False,
            "filename": filename,
            "size": size,
            "extension": ext,
            "error": f"File size ({size / (1024**2):.1f} MB) exceeds the "
                     f"{MAX_FILE_SIZE_MB} MB limit.",
        }

    if ext not in SUPPORTED_IMAGE_FORMATS:
        return {
            "valid": False,
            "filename": filename,
            "size": size,
            "extension": ext,
            "error": f"Unsupported extension '{ext}'. "
                     f"Supported: {', '.join(SUPPORTED_IMAGE_FORMATS)}.",
        }

    return {
        "valid": True,
        "filename": filename,
        "size": size,
        "extension": ext,
        "error": None,
    }


def validate_image(file_path: Path) -> dict[str, Any]:
    """Open *file_path* with Pillow and verify it is a genuine image.

    Returns
    -------
    dict
        ``valid``, ``format``, ``width``, ``height``, ``mode``, ``error``.
    """
    try:
        with Image.open(file_path) as img:
            img.verify()  # lightweight integrity check

        # Re-open after verify (verify may close internal state)
        with Image.open(file_path) as img:
            return {
                "valid": True,
                "format": (img.format or "UNKNOWN").upper(),
                "width": img.width,
                "height": img.height,
                "mode": img.mode,
                "error": None,
            }

    except UnidentifiedImageError:
        return {
            "valid": False,
            "format": None,
            "width": None,
            "height": None,
            "mode": None,
            "error": "The file is not a recognised image. It may have been "
                     "renamed with an image extension but is not actually an image.",
        }
    except Exception as exc:
        return {
            "valid": False,
            "format": None,
            "width": None,
            "height": None,
            "mode": None,
            "error": f"Validation error: {exc}",
        }

