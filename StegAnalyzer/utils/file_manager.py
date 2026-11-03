"""
StegAnalyzer — File management utilities.

Handles upload persistence, working-copy creation, directory
initialisation and filename sanitisation.
"""

from __future__ import annotations

import os
import re
import shutil
import uuid
from pathlib import Path
from datetime import datetime, timezone

from utils.config import UPLOADS_DIR, EXTRACTED_DIR, REPORTS_DIR, ASSETS_DIR


def ensure_directories() -> None:
    """Create all required output directories if they do not exist."""
    for d in (UPLOADS_DIR, EXTRACTED_DIR, REPORTS_DIR, ASSETS_DIR):
        d.mkdir(parents=True, exist_ok=True)


def get_safe_filename(filename: str) -> str:
    """Sanitise *filename* to prevent path-traversal and special-char issues.

    Only alphanumeric characters, hyphens, underscores and dots are kept.
    """
    # Strip directory separators / traversal patterns
    name = os.path.basename(filename)
    name = re.sub(r"[^\w.\-]", "_", name)
    # Collapse consecutive underscores
    name = re.sub(r"_+", "_", name).strip("_")
    return name or "unnamed_file"


def save_upload(uploaded_file_bytes: bytes, original_name: str) -> Path:
    """Persist an uploaded file to the *uploads/* directory.

    Returns the absolute path to the saved file.
    """
    ensure_directories()
    safe_name = get_safe_filename(original_name)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    unique_name = f"{timestamp}_{uuid.uuid4().hex[:8]}_{safe_name}"
    dest = UPLOADS_DIR / unique_name
    dest.write_bytes(uploaded_file_bytes)
    return dest


def create_working_copy(original_path: Path) -> Path:
    """Create a disposable copy next to the original for analysis.

    The original evidence file is never modified.
    """
    stem = original_path.stem
    suffix = original_path.suffix
    copy_name = f"{stem}_workcopy_{uuid.uuid4().hex[:6]}{suffix}"
    copy_path = original_path.parent / copy_name
    shutil.copy2(original_path, copy_path)
    return copy_path


def cleanup_working_copy(path: Path) -> None:
    """Remove a working copy after analysis."""
    if path.exists() and "_workcopy_" in path.name:
        path.unlink(missing_ok=True)


def get_file_size_str(size_bytes: int) -> str:
    """Return a human-readable file-size string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 ** 2):.2f} MB"


def create_extraction_dir(investigation_id: str) -> Path:
    """Create a unique extraction sub-directory and return its path."""
    ensure_directories()
    d = EXTRACTED_DIR / investigation_id
    d.mkdir(parents=True, exist_ok=True)
    return d

