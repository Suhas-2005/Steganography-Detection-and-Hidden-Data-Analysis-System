"""
StegAnalyzer — Centralized configuration constants.

All path constants are resolved relative to the project root so that every
module shares the same directory layout.
"""

import os
from pathlib import Path

# ── Application identity ────────────────────────────────────────────────
APP_NAME: str = "STEGANALYZER"
APP_SUBTITLE: str = "Digital Forensics and Hidden Data Investigation"
VERSION: str = "1.0.0"

# ── Project root ────────────────────────────────────────────────────────
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent

# ── Working directories ────────────────────────────────────────────────
UPLOADS_DIR: Path = PROJECT_ROOT / "uploads"
EXTRACTED_DIR: Path = PROJECT_ROOT / "extracted"
REPORTS_DIR: Path = PROJECT_ROOT / "reports"
ASSETS_DIR: Path = PROJECT_ROOT / "assets"
TOOLS_DIR: Path = PROJECT_ROOT / "tools"

# Automatically ensure portable tools directories are registered in PATH
_LOCAL_TOOL_PATHS = [
    str(TOOLS_DIR),
    str(TOOLS_DIR / "steghide"),
    str(TOOLS_DIR / "binwalk"),
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\ExifTool"),
    r"C:\Program Files\ExifTool",
    r"C:\Program Files (x86)\ExifTool",
]

for _p in _LOCAL_TOOL_PATHS:
    if os.path.isdir(_p) and _p not in os.environ.get("PATH", ""):
        os.environ["PATH"] = f"{_p}{os.pathsep}{os.environ.get('PATH', '')}"

# ── Supported formats ──────────────────────────────────────────────────
SUPPORTED_IMAGE_FORMATS: list[str] = [".jpg", ".jpeg", ".png", ".bmp"]
STEGHIDE_SUPPORTED_FORMATS: list[str] = [".jpg", ".jpeg", ".bmp"]

# ── Limits ──────────────────────────────────────────────────────────────
MAX_FILE_SIZE_MB: int = 50
MAX_FILE_SIZE_BYTES: int = MAX_FILE_SIZE_MB * 1024 * 1024

# ── Subprocess defaults ────────────────────────────────────────────────
DEFAULT_TIMEOUT: int = 60  # seconds

# ── External tools ──────────────────────────────────────────────────────
TOOL_NAMES: dict[str, str] = {
    "exiftool": "ExifTool",
    "binwalk": "Binwalk",
    "steghide": "Steghide",
}

# ── Theme colours (Forest & Earth 4-colour palette) ─────────────────────
THEME = {
    "forest_green": "#15370D",
    "sage_green": "#728E6D",
    "muted_gold": "#E5CD82",
    "soft_butter_yellow": "#FFF2B4",
    # Semantic mappings
    "bg_primary": "#FFF2B4",
    "bg_card": "#728E6D",
    "bg_header": "#15370D",
    "text_dark": "#15370D",
    "text_light": "#FFF2B4",
    "accent": "#15370D",
    "accent_gold": "#E5CD82",
}
