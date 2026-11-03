"""
StegAnalyzer – Steganography Detection and Hidden Data Analysis System
Forest & Earth 4-Colour Themed Forensic Workspace.

Palette:
  • Forest Green:      #15370D (Headers, primary buttons, strong contrast typography)
  • Sage Green:        #728E6D (Feature cards, borders, accents)
  • Muted Gold:        #E5CD82 (Card hover states, evidence cards, secondary accents)
  • Soft Butter Yellow:#FFF2B4 (Primary application & canvas background)
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import streamlit as st
from PIL import Image

# Configuration & Utilities
from utils.config import (
    APP_NAME,
    APP_SUBTITLE,
    MAX_FILE_SIZE_BYTES,
    MAX_FILE_SIZE_MB,
    SUPPORTED_IMAGE_FORMATS,
    VERSION,
)
from utils.file_manager import (
    cleanup_working_copy,
    create_extraction_dir,
    create_working_copy,
    ensure_directories,
    get_file_size_str,
    save_upload,
)
from utils.tool_checker import check_all_tools

# Forensic Modules
from modules.file_validator import validate_image, validate_upload
from modules.hash_generator import calculate_sha256
from modules.metadata_analyzer import extract_metadata, parse_gps_coordinates, get_metadata_summary
from modules.binwalk_analyzer import analyze_embedded
from modules.steghide_analyzer import is_format_supported, get_format_explanation, inspect_file, extract_data
from modules.history_manager import add_investigation
from modules.report_generator import generate_forensic_report


# ── Page Configuration & Forest & Earth Styling ───────────────────────────────

st.set_page_config(
    page_title=f"{APP_NAME} — Forensic Workspace",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
    /* ── BASE PALETTE & APP BACKGROUND (#FFF2B4) ────────────────────────── */
    html, body, .stApp, [data-testid="stAppViewContainer"], [data-testid="stHeader"], [data-testid="stToolbar"], .main, .block-container {
        background-color: #FFF2B4 !important;
        color: #15370D !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }

    /* Remove sidebar completely */
    [data-testid="stSidebar"], section[data-testid="stSidebar"] {
        display: none !important;
    }

    /* Centered desktop container */
    .block-container {
        max-width: 1040px;
        padding-top: 1.4rem;
        padding-bottom: 3rem;
    }

    /* ── TOP NAVIGATION BAR (#15370D Forest Green) ──────────────────────── */
    .top-nav {
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: #15370D;
        padding: 0.9rem 1.6rem;
        border-radius: 12px;
        border: 1px solid #728E6D;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 6px -1px rgba(21, 55, 13, 0.2);
    }
    .top-nav-brand {
        display: flex;
        align-items: center;
        gap: 0.6rem;
        font-weight: 800;
        font-size: 1.3rem;
        color: #FFF2B4;
        letter-spacing: -0.01em;
    }
    .top-nav-icon {
        color: #E5CD82;
        font-size: 1.4rem;
    }
    .top-nav-subtitle {
        font-size: 0.88rem;
        color: #FFF2B4;
        font-weight: 500;
        opacity: 0.95;
    }

    /* ── STAGE 1: WELCOME BANNER (#E5CD82 Muted Gold) ───────────────────── */
    .welcome-card {
        text-align: center;
        background: #E5CD82;
        border: 1px solid #728E6D;
        border-radius: 12px;
        padding: 2.2rem 1.6rem 1.8rem 1.6rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 8px rgba(21, 55, 13, 0.08);
    }
    .welcome-title {
        font-size: 1.75rem;
        font-weight: 800;
        color: #15370D;
        margin: 0;
    }
    .welcome-sub {
        font-size: 0.95rem;
        color: #15370D;
        font-weight: 700;
        margin-top: 0.35rem;
        margin-bottom: 0.6rem;
    }
    .welcome-desc {
        font-size: 0.9rem;
        color: #15370D;
        max-width: 620px;
        margin: 0 auto;
        line-height: 1.5;
    }

    /* ── FILE UPLOADER CONTAINER (#E5CD82) ──────────────────────────────── */
    [data-testid="stFileUploader"] {
        background-color: #E5CD82 !important;
        border: 2px dashed #15370D !important;
        border-radius: 12px !important;
        padding: 1.25rem !important;
    }
    [data-testid="stFileUploaderDropzone"] {
        background-color: #E5CD82 !important;
        border: none !important;
    }
    [data-testid="stFileUploaderDropzone"] * {
        color: #15370D !important;
    }
    [data-testid="stFileUploaderDropzone"] button {
        background-color: #15370D !important;
        color: #FFF2B4 !important;
        border: 1px solid #15370D !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
    }
    [data-testid="stFileUploaderDropzone"] button:hover {
        background-color: #728E6D !important;
        color: #FFF2B4 !important;
    }

    /* ── STAGE 2: ACTIVE EVIDENCE BOX (#E5CD82) ─────────────────────────── */
    .evidence-card {
        background: #E5CD82;
        border: 1px solid #728E6D;
        border-radius: 12px;
        padding: 1.25rem 1.5rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 3px 6px rgba(21, 55, 13, 0.08);
        color: #15370D;
    }
    .evidence-header {
        font-size: 0.9rem;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #15370D;
        margin-bottom: 0.75rem;
    }
    .hash-badge {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.8rem;
        background: #FFF2B4;
        padding: 0.4rem 0.6rem;
        border-radius: 6px;
        border: 1px solid #728E6D;
        word-break: break-all;
        color: #15370D;
        display: block;
    }

    /* Section Header */
    .section-title {
        font-size: 1.15rem;
        font-weight: 800;
        color: #15370D;
        letter-spacing: -0.01em;
        margin-top: 1rem;
        margin-bottom: 0.85rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    /* ── FEATURE CARDS (#728E6D Sage Green -> #E5CD82 on hover) ──────────── */
    .feature-card {
        background: #728E6D;
        border: 1px solid #15370D;
        border-radius: 12px;
        padding: 1.25rem 1rem;
        text-align: center;
        min-height: 175px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        box-shadow: 0 3px 6px rgba(21, 55, 13, 0.08);
        transition: all 0.2s ease-in-out;
        color: #FFF2B4;
    }
    .feature-card:hover {
        background: #E5CD82 !important;
        border-color: #15370D !important;
        box-shadow: 0 8px 16px rgba(21, 55, 13, 0.16) !important;
        transform: translateY(-3px);
    }
    .feature-card:hover .feature-title,
    .feature-card:hover .feature-desc,
    .feature-card:hover .feature-icon {
        color: #15370D !important;
    }
    .feature-icon {
        font-size: 1.6rem;
        color: #E5CD82;
        margin-bottom: 0.4rem;
        display: inline-block;
        transition: color 0.2s ease;
    }
    .feature-title {
        font-size: 0.95rem;
        font-weight: 700;
        color: #FFF2B4;
        margin-bottom: 0.35rem;
        transition: color 0.2s ease;
    }
    .feature-desc {
        font-size: 0.8rem;
        color: #FFF2B4;
        line-height: 1.35;
        margin-bottom: 0.75rem;
        flex-grow: 1;
        transition: color 0.2s ease;
        opacity: 0.95;
    }

    /* ── RESULTS PANEL (#E5CD82 Muted Gold) ─────────────────────────────── */
    .results-panel {
        background: #E5CD82;
        border: 1px solid #728E6D;
        border-radius: 12px;
        padding: 1.5rem;
        margin-top: 1.25rem;
        box-shadow: 0 4px 8px rgba(21, 55, 13, 0.08);
        color: #15370D;
    }

    /* ── BUTTON STYLING (Strictly Palette-Compliant) ──────────────────────── */
    /* Primary buttons (#15370D background, #FFF2B4 text, #728E6D hover) */
    div.stButton > button, div.stButton > button[kind="primary"] {
        background-color: #15370D !important;
        color: #FFF2B4 !important;
        border: 1px solid #15370D !important;
        border-radius: 8px !important;
        font-weight: 700 !important;
        transition: all 0.15s ease-in-out !important;
    }
    div.stButton > button:hover, div.stButton > button[kind="primary"]:hover {
        background-color: #728E6D !important;
        color: #FFF2B4 !important;
        border-color: #15370D !important;
    }

    /* Secondary buttons (#E5CD82 background, #15370D text, #728E6D border) */
    div.stButton > button[kind="secondary"] {
        background-color: #E5CD82 !important;
        color: #15370D !important;
        border: 1px solid #728E6D !important;
        border-radius: 8px !important;
        font-weight: 700 !important;
    }
    div.stButton > button[kind="secondary"]:hover {
        background-color: #FFF2B4 !important;
        color: #15370D !important;
        border-color: #15370D !important;
    }

    /* Download buttons (#15370D background, #FFF2B4 text, #E5CD82 border) */
    [data-testid="stDownloadButton"] > button {
        background-color: #15370D !important;
        color: #FFF2B4 !important;
        border: 1px solid #E5CD82 !important;
        border-radius: 8px !important;
        font-weight: 700 !important;
    }
    [data-testid="stDownloadButton"] > button:hover {
        background-color: #728E6D !important;
        color: #FFF2B4 !important;
    }

    /* ── TABS STYLING ───────────────────────────────────────────────────── */
    .stTabs [data-baseweb="tab-list"] {
        background-color: transparent !important;
        border-bottom: 2px solid #728E6D !important;
        gap: 6px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #728E6D !important;
        color: #FFF2B4 !important;
        border-radius: 8px 8px 0 0 !important;
        padding: 8px 18px !important;
        border: 1px solid #15370D !important;
        border-bottom: none !important;
        font-weight: 700 !important;
    }
    .stTabs [data-baseweb="tab"]:hover {
        background-color: #E5CD82 !important;
        color: #15370D !important;
    }
    .stTabs [data-baseweb="tab"][aria-selected="true"] {
        background-color: #15370D !important;
        color: #FFF2B4 !important;
        border-bottom: 3px solid #E5CD82 !important;
    }

    /* ── TABLES & DATAFRAMES (Never white!) ──────────────────────────────── */
    table {
        background-color: #FFF2B4 !important;
        color: #15370D !important;
        border: 1px solid #728E6D !important;
        border-radius: 8px !important;
        width: 100% !important;
    }
    th {
        background-color: #15370D !important;
        color: #FFF2B4 !important;
        border: 1px solid #728E6D !important;
        font-weight: 700 !important;
        padding: 8px 12px !important;
    }
    td {
        background-color: #FFF2B4 !important;
        color: #15370D !important;
        border: 1px solid #E5CD82 !important;
        padding: 8px 12px !important;
    }
    tr:nth-child(even) td {
        background-color: #F8E89D !important;
    }

    [data-testid="stDataFrame"] {
        background-color: #FFF2B4 !important;
        border: 1px solid #728E6D !important;
        border-radius: 8px !important;
    }

    /* ── EXPANDERS & TECHNICAL CODE BLOCKS ───────────────────────────────── */
    [data-testid="stExpander"] {
        background-color: #FFF2B4 !important;
        border: 1px solid #728E6D !important;
        border-radius: 8px !important;
    }
    [data-testid="stExpander"] summary {
        color: #15370D !important;
        font-weight: 700 !important;
    }
    code, pre, .stCodeBlock {
        background-color: #15370D !important;
        color: #FFF2B4 !important;
        border: 1px solid #728E6D !important;
        border-radius: 6px !important;
    }

    /* ── TEXT INPUTS & TEXT AREAS ────────────────────────────────────────── */
    input[type="text"], input[type="password"] {
        background-color: #FFF2B4 !important;
        color: #15370D !important;
        border: 1px solid #728E6D !important;
        border-radius: 6px !important;
    }
    input[type="text"]:focus, input[type="password"]:focus {
        border: 2px solid #15370D !important;
        outline: none !important;
    }
    textarea {
        background-color: #FFF2B4 !important;
        color: #15370D !important;
        border: 2px solid #15370D !important;
        border-radius: 8px !important;
    }

    /* ── ALERTS & STATUS PANELS ─────────────────────────────────────────── */
    [data-testid="stAlert"] {
        border-radius: 8px !important;
        font-weight: 600 !important;
    }
    .stSuccess, [data-testid="stAlert"][kind="success"] {
        background-color: #728E6D !important;
        color: #FFF2B4 !important;
        border: 1px solid #15370D !important;
    }
    .stSuccess *, [data-testid="stAlert"][kind="success"] * {
        color: #FFF2B4 !important;
    }
    .stWarning, [data-testid="stAlert"][kind="warning"] {
        background-color: #E5CD82 !important;
        color: #15370D !important;
        border: 2px solid #15370D !important;
    }
    .stWarning *, [data-testid="stAlert"][kind="warning"] * {
        color: #15370D !important;
    }
    .stInfo, [data-testid="stAlert"][kind="info"] {
        background-color: #E5CD82 !important;
        color: #15370D !important;
        border: 1px solid #728E6D !important;
    }
    .stInfo *, [data-testid="stAlert"][kind="info"] * {
        color: #15370D !important;
    }
    .stError, [data-testid="stAlert"][kind="error"] {
        background-color: #E5CD82 !important;
        color: #15370D !important;
        border: 2px solid #15370D !important;
    }
    .stError *, [data-testid="stAlert"][kind="error"] * {
        color: #15370D !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

ensure_directories()


# ── Session State Management ──────────────────────────────────────────────────

if "current_file_sig" not in st.session_state:
    st.session_state.current_file_sig = None

if "image_record" not in st.session_state:
    st.session_state.image_record = None

if "active_operation" not in st.session_state:
    st.session_state.active_operation = None

if "results_cache" not in st.session_state:
    st.session_state.results_cache = {}


# ── TOP NAVIGATION BAR (#15370D Forest Green) ─────────────────────────────────

st.markdown(
    f"""
    <div class="top-nav">
        <div class="top-nav-brand">
            <span class="top-nav-icon">🛡️</span> {APP_NAME}
        </div>
        <div class="top-nav-subtitle">
            {APP_SUBTITLE}
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ── STAGE ONE: IMAGE UPLOAD DASHBOARD (Warm & Centered) ───────────────────────

if st.session_state.image_record is None:
    st.markdown(
        """
        <div class="welcome-card">
            <h1 class="welcome-title">Image Investigation Dashboard</h1>
            <div class="welcome-sub">Steganography & Hidden Data Forensics Workspace</div>
            <p class="welcome-desc">
                Upload an image to examine its technical metadata, inspect carrier capacity, 
                detect embedded signatures, and extract concealed payloads.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    upload_col1, upload_col2, upload_col3 = st.columns([1, 4, 1])
    with upload_col2:
        uploaded_file = st.file_uploader(
            "Select Evidence Image File",
            type=["jpg", "jpeg", "png", "bmp"],
            help=f"Supported carrier formats: JPG, JPEG, PNG, BMP (Max: {MAX_FILE_SIZE_MB}MB)",
            key="primary_uploader",
        )

    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        file_name = uploaded_file.name
        file_size = len(file_bytes)

        # 1. Size & Extension validation
        val_up = validate_upload(file_name, file_size)
        if not val_up["valid"]:
            st.error(f"❌ File rejected: {val_up['error']}")
        else:
            # 2. Save original evidence
            saved_original = save_upload(file_bytes, file_name)

            # 3. Content signature validation via Pillow
            val_img = validate_image(saved_original)
            if not val_img["valid"]:
                st.error(f"❌ Content verification failed: {val_img['error']}")
            else:
                # 4. SHA-256 fingerprinting
                sha256_hash = calculate_sha256(saved_original)
                file_sig = f"{file_name}_{file_size}_{sha256_hash[:8]}"

                st.session_state.image_record = {
                    "original_path": str(saved_original),
                    "filename": file_name,
                    "format": val_img["format"],
                    "dimensions": f"{val_img['width']} × {val_img['height']} px",
                    "width": val_img["width"],
                    "height": val_img["height"],
                    "mode": val_img["mode"],
                    "size_bytes": file_size,
                    "size_str": get_file_size_str(file_size),
                    "sha256": sha256_hash,
                    "investigation_id": f"INV-{sha256_hash[:8].upper()}",
                }
                st.session_state.current_file_sig = file_sig
                st.session_state.active_operation = None
                st.session_state.results_cache = {}
                st.rerun()


# ── STAGE TWO: IMAGE UPLOADED (Dynamic Forensic Workspace) ────────────────────

else:
    img_data = st.session_state.image_record
    inv_id = img_data["investigation_id"]

    # 1. Selected Image Header Card (#E5CD82 Muted Gold)
    st.markdown('<div class="evidence-card">', unsafe_allow_html=True)
    st.markdown('<div class="evidence-header">Active Evidence File</div>', unsafe_allow_html=True)

    ev_col1, ev_col2, ev_col3 = st.columns([1, 2.2, 1.2])

    with ev_col1:
        st.image(img_data["original_path"], use_container_width=True)

    with ev_col2:
        st.markdown(f"**Filename:** `{img_data['filename']}`")
        st.markdown(f"**Format:** `{img_data['format']}` &nbsp;|&nbsp; **Dimensions:** `{img_data['dimensions']}`")
        st.markdown(f"**File Size:** `{img_data['size_str']}` ({img_data['size_bytes']:,} bytes)")
        with st.expander("🔑 SHA-256 Cryptographic Evidence Digest"):
            st.markdown(f'<span class="hash-badge">{img_data["sha256"]}</span>', unsafe_allow_html=True)
            st.caption("Computed before analysis. Evidence integrity verified.")

    with ev_col3:
        st.write("")
        if st.button("🔄 Change Image", use_container_width=True, type="secondary"):
            st.session_state.image_record = None
            st.session_state.active_operation = None
            st.session_state.results_cache = {}
            st.session_state.current_file_sig = None
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)

    # 2. Choose Analysis Operation (Four Clickable Feature Cards)
    st.markdown('<div class="section-title">CHOOSE AN ANALYSIS OPERATION</div>', unsafe_allow_html=True)

    card_c1, card_c2, card_c3, card_c4 = st.columns(4)

    # CARD 1: Steganography Detection (#728E6D Sage Green)
    with card_c1:
        st.markdown(
            """
            <div class="feature-card">
                <div>
                    <div class="feature-icon">🔍</div>
                    <div class="feature-title">Steganography Detection</div>
                    <div class="feature-desc">Inspect image carrier for data hidden via transform-domain embedding (Steghide).</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Inspect Steganography", key="btn_card_steg", use_container_width=True):
            st.session_state.active_operation = "steg_detect"

    # CARD 2: Hidden Text Extraction (#728E6D Sage Green)
    with card_c2:
        st.markdown(
            """
            <div class="feature-card">
                <div>
                    <div class="feature-icon">💬</div>
                    <div class="feature-title">Hidden Text Extraction</div>
                    <div class="feature-desc">Recover embedded messages or payloads using authorized passphrases.</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Extract Content", key="btn_card_extract", use_container_width=True):
            st.session_state.active_operation = "steg_extract"

    # CARD 3: Metadata Analysis (#728E6D Sage Green)
    with card_c3:
        st.markdown(
            """
            <div class="feature-card">
                <div>
                    <div class="feature-icon">📸</div>
                    <div class="feature-title">Metadata Analysis</div>
                    <div class="feature-desc">Extract camera settings, timestamps, software history, and GPS location.</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Analyze Metadata", key="btn_card_meta", use_container_width=True):
            st.session_state.active_operation = "metadata"

    # CARD 4: Embedded File Detection (#728E6D Sage Green)
    with card_c4:
        st.markdown(
            """
            <div class="feature-card">
                <div>
                    <div class="feature-icon">📦</div>
                    <div class="feature-title">Embedded File Detection</div>
                    <div class="feature-desc">Scan binary offsets for concatenated zip archives, executables, or files (Binwalk).</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Scan Embedded Files", key="btn_card_binwalk", use_container_width=True):
            st.session_state.active_operation = "binwalk"

    # 3. Comprehensive "ANALYZE ALL" Action
    st.write("")
    all_col1, all_col2, all_col3 = st.columns([1, 2, 1])
    with all_col2:
        if st.button("⚡ ANALYZE ALL OPERATIONS", type="primary", use_container_width=True):
            st.session_state.active_operation = "analyze_all"

    # ── 4. DYNAMIC OPERATION RESULTS SECTION (#E5CD82 Results Panel) ───────────

    active_op = st.session_state.active_operation

    if active_op is not None:
        st.markdown('<div class="results-panel">', unsafe_allow_html=True)
        res_header_col1, res_header_col2 = st.columns([3, 1])

        with res_header_col2:
            if st.button("✕ Close Results", key="btn_close_res", use_container_width=True):
                st.session_state.active_operation = None
                st.rerun()

        # Shared working copy logic for isolated, non-destructive execution
        original_p = Path(img_data["original_path"])

        # ── OPERATION 1: STEGANOGRAPHY DETECTION ──────────────────────────────
        if active_op == "steg_detect":
            with res_header_col1:
                st.markdown("### 🔍 Steganography Detection (Steghide)")

            is_supp = is_format_supported(original_p)
            if not is_supp:
                st.info(
                    f"**Carrier Format Not Supported:** The image is formatted as **{img_data['format']}**. "
                    f"Steghide operates specifically on JPEG and BMP images. "
                    f"PNG carrier images are not supported by Steghide."
                )
            else:
                if "steg_inspect" not in st.session_state.results_cache:
                    with st.spinner("Running Steghide inspection on working copy..."):
                        work_copy = create_working_copy(original_p)
                        try:
                            st.session_state.results_cache["steg_inspect"] = inspect_file(work_copy)
                        finally:
                            cleanup_working_copy(work_copy)

                res = st.session_state.results_cache["steg_inspect"]
                if not res.get("tool_available"):
                    st.warning("⚠️ Steghide is not installed or available on PATH.")
                else:
                    if res.get("embedded"):
                        st.warning("⚠️ **Potential Steganographic Indicator Detected:** Steghide reported valid payload headers or embedding markers.")
                    else:
                        st.success("✅ **Inspection Complete:** No obvious unencrypted embedded signature detected with blank passphrase.")

                    st.markdown(f"**Analysis Finding:** {res.get('explanation')}")
                    if res.get("capacity"):
                        st.markdown(f"**Embedding Capacity:** `{res['capacity']}`")

                    with st.expander("Technical Command Output (Steghide Info)"):
                        st.code(res.get("raw_output", "No output captured"), language="text")

        # ── OPERATION 2: HIDDEN TEXT EXTRACTION ───────────────────────────────
        elif active_op == "steg_extract":
            with res_header_col1:
                st.markdown("### 💬 Hidden Text & Payload Extraction")

            is_supp = is_format_supported(original_p)
            if not is_supp:
                st.info(
                    f"**Carrier Format Not Supported:** This image is a **{img_data['format']}**. "
                    f"Steghide extraction is only available for JPEG and BMP carriers."
                )
            else:
                st.write("Extract hidden text or embedded files by providing the passphrase (leave blank if none was set).")
                pass_c1, pass_c2 = st.columns([2.5, 1.2])

                with pass_c1:
                    user_pass = st.text_input("Steghide Passphrase", type="password", placeholder="Enter passphrase (optional)", key="steg_pass_in")
                with pass_c2:
                    st.write("")
                    extract_trigger = st.button("🔓 Extract Hidden Content", type="primary", use_container_width=True)

                if extract_trigger:
                    with st.spinner("Executing extraction with Steghide..."):
                        work_copy = create_working_copy(original_p)
                        ext_dir = create_extraction_dir(inv_id)
                        try:
                            ext_result = extract_data(work_copy, user_pass, ext_dir)
                            st.session_state.results_cache["steg_extract"] = ext_result
                        finally:
                            cleanup_working_copy(work_copy)

                curr_ext = st.session_state.results_cache.get("steg_extract")
                if curr_ext:
                    st.write("")
                    if curr_ext["success"]:
                        st.success(f"🎉 {curr_ext['message']}")
                        if curr_ext.get("is_text") and curr_ext.get("extracted_text"):
                            st.markdown("##### Recovered Hidden Text Message:")
                            st.text_area("Decoded Payload (UTF-8)", curr_ext["extracted_text"], height=130, disabled=True)
                        else:
                            st.info(f"Binary file recovered ({curr_ext.get('extracted_file_size', 0)} bytes).")

                        if curr_ext.get("extracted_file_path") and Path(curr_ext["extracted_file_path"]).exists():
                            p_bytes = Path(curr_ext["extracted_file_path"]).read_bytes()
                            st.download_button(
                                label="💾 Download Extracted File",
                                data=p_bytes,
                                file_name=f"recovered_{Path(img_data['filename']).stem}.bin",
                                mime="application/octet-stream",
                            )
                    else:
                        st.error(f"❌ {curr_ext['message']}")
                        with st.expander("Technical Command Output"):
                            st.code(curr_ext.get("raw_output", "No output."), language="text")

        # ── OPERATION 3: METADATA ANALYSIS ────────────────────────────────────
        elif active_op == "metadata":
            with res_header_col1:
                st.markdown("### 📸 Image Metadata Analysis (ExifTool & Pillow)")

            if "metadata" not in st.session_state.results_cache:
                with st.spinner("Extracting image metadata..."):
                    work_copy = create_working_copy(original_p)
                    try:
                        m_res = extract_metadata(work_copy)
                        m_sum = get_metadata_summary(m_res)
                        g_coords = parse_gps_coordinates(m_res.get("metadata", {}))
                        st.session_state.results_cache["metadata"] = {
                            "results": m_res,
                            "summary": m_sum,
                            "gps": g_coords,
                        }
                    finally:
                        cleanup_working_copy(work_copy)

            meta_data = st.session_state.results_cache["metadata"]
            m_res = meta_data["results"]
            m_sum = meta_data["summary"]
            g_coords = meta_data["gps"]

            if not m_res.get("tool_available"):
                st.warning("ExifTool is not installed. Showing basic Pillow image properties.")
            else:
                if m_sum.get("flags"):
                    for fl in m_sum["flags"]:
                        st.warning(fl)

                key_findings = m_res.get("key_findings", {})
                table_rows = []

                # Format basic properties
                table_rows.append({"Category": "Basic Info", "Property": "Filename", "Value": img_data["filename"]})
                table_rows.append({"Category": "Basic Info", "Property": "Image Format", "Value": img_data["format"]})
                table_rows.append({"Category": "Basic Info", "Property": "Dimensions", "Value": img_data["dimensions"]})
                table_rows.append({"Category": "Basic Info", "Property": "File Size", "Value": img_data["size_str"]})
                table_rows.append({"Category": "Basic Info", "Property": "Color Mode", "Value": img_data["mode"]})
                table_rows.append({"Category": "Basic Info", "Property": "SHA-256 Digest", "Value": img_data["sha256"]})

                # Append ExifTool fields
                for cat, tags in key_findings.items():
                    for k, v in tags.items():
                        table_rows.append({"Category": cat, "Property": k, "Value": str(v)})

                st.table(table_rows)

                if g_coords:
                    st.info(f"📍 **Embedded GPS Location:** `{g_coords['formatted']}` (Altitude: {g_coords.get('altitude', 'N/A')})")

                with st.expander("Technical Raw Metadata Output"):
                    st.code(m_res.get("raw_output", "No raw output available"), language="text")

        # ── OPERATION 4: EMBEDDED FILE DETECTION ──────────────────────────────
        elif active_op == "binwalk":
            with res_header_col1:
                st.markdown("### 📦 Embedded File & Signature Detection (Binwalk)")

            if "binwalk" not in st.session_state.results_cache:
                with st.spinner("Scanning file structures and signatures with Binwalk..."):
                    work_copy = create_working_copy(original_p)
                    try:
                        st.session_state.results_cache["binwalk"] = analyze_embedded(work_copy)
                    finally:
                        cleanup_working_copy(work_copy)

            b_res = st.session_state.results_cache["binwalk"]
            if not b_res.get("tool_available"):
                st.warning("Binwalk is not installed or available on PATH.")
            else:
                if b_res.get("has_suspicious_indicators"):
                    st.warning("⚠️ **Potential Indicator Identified:** Concatenated or trailing file signatures detected at non-zero offsets.")
                else:
                    st.success("✅ **Scan Complete:** No suspicious trailing structures or archive signatures found.")

                st.markdown(f"**Scan Finding:** {b_res.get('summary')}")
                st.caption("Forensic Note: Signature matches indicate recognized file headers (e.g. appended ZIP archives past EOF). They are potential indicators requiring verification and do not automatically prove malicious activity.")

                sigs = b_res.get("signatures", [])
                if sigs:
                    table_sigs = []
                    for s in sigs:
                        table_sigs.append({
                            "Decimal Offset": str(s.get("offset_dec")),
                            "Hex Offset": str(s.get("offset_hex")),
                            "Detected File Signature / Type": str(s.get("description")),
                        })
                    st.table(table_sigs)
                else:
                    st.info("No recognizable embedded signatures identified.")

                with st.expander("Technical Scan Output (Binwalk stdout)"):
                    st.code(b_res.get("raw_output", "No output captured"), language="text")

        # ── OPERATION 5: ANALYZE ALL (Consolidated Investigation) ─────────────
        elif active_op == "analyze_all":
            with res_header_col1:
                st.markdown("### ⚡ Consolidated Forensic Investigation")

            # Execute all tools if not already in cache
            with st.spinner("Executing complete multi-vector forensic pipeline..."):
                work_copy = create_working_copy(original_p)
                try:
                    if "metadata" not in st.session_state.results_cache:
                        m_res = extract_metadata(work_copy)
                        m_sum = get_metadata_summary(m_res)
                        g_coords = parse_gps_coordinates(m_res.get("metadata", {}))
                        st.session_state.results_cache["metadata"] = {"results": m_res, "summary": m_sum, "gps": g_coords}

                    if "binwalk" not in st.session_state.results_cache:
                        st.session_state.results_cache["binwalk"] = analyze_embedded(work_copy)

                    if "steg_inspect" not in st.session_state.results_cache:
                        st.session_state.results_cache["steg_inspect"] = inspect_file(work_copy)
                finally:
                    cleanup_working_copy(work_copy)

            all_meta = st.session_state.results_cache["metadata"]
            all_bin = st.session_state.results_cache["binwalk"]
            all_steg = st.session_state.results_cache["steg_inspect"]
            ext_cache = st.session_state.results_cache.get("steg_extract", {})

            # Overall Status Determination
            indicators_found = []
            if all_bin.get("has_suspicious_indicators"):
                indicators_found.append("Binwalk detected trailing/embedded file signatures.")
            if all_steg.get("embedded"):
                indicators_found.append("Steghide reported potential embedded content.")

            if ext_cache.get("success"):
                overall_status = "Hidden content extracted"
            elif indicators_found:
                overall_status = "Potential indicator found"
            else:
                overall_status = "No known indicator reported"

            # Executive Status Box
            if overall_status == "Hidden content extracted":
                st.success(f"**Overall Status:** {overall_status}")
            elif overall_status == "Potential indicator found":
                st.warning(f"**Overall Status:** {overall_status} ({len(indicators_found)} anomaly vectors)")
            else:
                st.info(f"**Overall Status:** {overall_status}")

            # Consolidated Tabs
            c_tab1, c_tab2, c_tab3, c_tab4 = st.tabs(["Overview & Metadata", "Steganography", "Embedded Signatures", "Extracted Data"])

            with c_tab1:
                kf = all_meta["results"].get("key_findings", {})
                camera = kf.get("Camera Info", {})
                cam_str = f"{camera.get('Make', '')} {camera.get('Model', '')}".strip() or "Not recorded"
                dt = kf.get("Date / Time", {})
                date_str = dt.get("DateTimeOriginal") or dt.get("CreateDate") or "Not recorded"
                gps_str = all_meta["gps"]["formatted"] if all_meta["gps"] else "Not present"

                st.table([
                    {"Property": "Filename", "Value": img_data["filename"]},
                    {"Property": "Image Format", "Value": img_data["format"]},
                    {"Property": "Dimensions", "Value": img_data["dimensions"]},
                    {"Property": "File Size", "Value": img_data["size_str"]},
                    {"Property": "Camera Model", "Value": cam_str},
                    {"Property": "Date & Time", "Value": str(date_str)},
                    {"Property": "GPS Location", "Value": gps_str},
                    {"Property": "SHA-256 Digest", "Value": img_data["sha256"]},
                ])

            with c_tab2:
                if not is_format_supported(original_p):
                    st.info(f"Steghide carrier analysis is not supported for {img_data['format']}. (JPEG and BMP only).")
                else:
                    st.markdown(f"**Carrier Inspection:** {all_steg.get('explanation')}")
                    if all_steg.get("capacity"):
                        st.markdown(f"**Embedding Capacity:** `{all_steg['capacity']}`")

            with c_tab3:
                sigs = all_bin.get("signatures", [])
                st.markdown(f"**Binwalk Summary:** {all_bin.get('summary')}")
                if sigs:
                    st.table([
                        {"Offset (Dec)": str(s.get("offset_dec")), "Offset (Hex)": str(s.get("offset_hex")), "Signature": str(s.get("description"))}
                        for s in sigs
                    ])
                else:
                    st.info("No recognizable embedded signatures identified.")

            with c_tab4:
                if ext_cache and ext_cache.get("success"):
                    st.success(f"Extracted payload: {ext_cache.get('extracted_file_size', 0)} bytes")
                    if ext_cache.get("is_text"):
                        st.text_area("Decoded Text", ext_cache["extracted_text"], height=100, disabled=True)
                else:
                    st.info("No payload extracted. Use the **Hidden Text Extraction** card to provide a passphrase if applicable.")

            # Compile Investigation Record & PDF Export
            tools_info = check_all_tools()
            timestamp_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            investigation_record = {
                "investigation_id": inv_id,
                "timestamp": timestamp_now,
                "filename": img_data["filename"],
                "file_format": img_data["format"],
                "file_size_str": img_data["size_str"],
                "dimensions": img_data["dimensions"],
                "color_mode": img_data["mode"],
                "sha256": img_data["sha256"],
                "overall_status": overall_status,
                "overall_summary": f"Investigation of '{img_data['filename']}' completed with status: {overall_status}.",
                "metadata_results": all_meta["results"],
                "binwalk_results": all_bin,
                "steghide_results": all_steg,
                "extraction_results": ext_cache,
                "tools_status": tools_info,
            }

            add_investigation(investigation_record)

            st.write("")
            try:
                pdf_doc = generate_forensic_report(investigation_record)
                st.download_button(
                    label="📄 Download Official PDF Forensic Report",
                    data=pdf_doc.read_bytes(),
                    file_name=f"StegAnalyzer_Report_{inv_id}.pdf",
                    mime="application/pdf",
                    type="primary",
                )
            except Exception as pdf_err:
                st.caption(f"PDF export error: {pdf_err}")

        # Individual PDF Report for Single Operations (if not Analyze All)
        if active_op != "analyze_all":
            st.write("")
            st.markdown("---")
            try:
                tools_info = check_all_tools()
                timestamp_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

                cached_meta = st.session_state.results_cache.get("metadata", {}).get("results", {})
                cached_bin = st.session_state.results_cache.get("binwalk", {})
                cached_steg = st.session_state.results_cache.get("steg_inspect", {})
                cached_ext = st.session_state.results_cache.get("steg_extract", {})

                op_record = {
                    "investigation_id": inv_id,
                    "timestamp": timestamp_now,
                    "filename": img_data["filename"],
                    "file_format": img_data["format"],
                    "file_size_str": img_data["size_str"],
                    "dimensions": img_data["dimensions"],
                    "color_mode": img_data["mode"],
                    "sha256": img_data["sha256"],
                    "overall_status": f"Completed: {active_op}",
                    "overall_summary": f"Investigation performed operation: {active_op} on '{img_data['filename']}'.",
                    "metadata_results": cached_meta,
                    "binwalk_results": cached_bin,
                    "steghide_results": cached_steg,
                    "extraction_results": cached_ext,
                    "tools_status": tools_info,
                }

                pdf_doc = generate_forensic_report(op_record)
                st.download_button(
                    label="📄 Download Investigation Report (PDF)",
                    data=pdf_doc.read_bytes(),
                    file_name=f"Report_{active_op}_{inv_id}.pdf",
                    mime="application/pdf",
                )
            except Exception as pdf_err:
                st.caption(f"PDF export error: {pdf_err}")

        st.markdown("</div>", unsafe_allow_html=True)
