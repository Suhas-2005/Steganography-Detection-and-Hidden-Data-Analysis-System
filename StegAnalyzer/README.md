# 🛡️ StegAnalyzer — Steganography Detection & Hidden Data Analysis System

> **A Comprehensive Digital Forensics Investigation Suite for Image Steganalysis, Concatenated File Carving, and Metadata Auditing.**  
> Built for college-level Cybersecurity and Digital Forensics research, laboratory analysis, and incident response.

---

## 📑 Table of Contents
1. [Project Overview](#-project-overview)
2. [Key Capabilities & Forensic Methodology](#-key-capabilities--forensic-methodology)
3. [Technology Stack](#-technology-stack)
4. [Architecture & Project Structure](#-architecture--project-structure)
5. [System Requirements & Tool Installation](#-system-requirements--tool-installation)
   - [Windows Installation](#windows-10--11-setup)
   - [Kali Linux / Debian Setup](#kali-linux--debian--ubuntu-setup)
6. [Quick Start Guide](#-quick-start-guide)
7. [Testing & Verification Suite](#-testing--verification-suite)
   - [Automated Unit & E2E Tests](#automated-unit--integration-tests)
   - [Forensic Test Cases (TEST 1 to TEST 7)](#forensic-test-matrix)
8. [Digital Forensics & Security Controls](#-digital-forensics--security-controls)
9. [Report Generation & Chain of Custody](#-report-generation--chain-of-custody)
10. [Academic Project Context](#-academic-project-context)

---

## 🔍 Project Overview

**StegAnalyzer** is a Python-based forensic investigation environment designed to uncover data concealed inside digital images using multiple steganographic and obfuscation vectors:

- **Appended Data / File Concatenation (EOF Injection)**: Identifies extra files, archives, or code hidden past the official End-Of-Image marker.
- **Transform-Domain Steganography**: Inspects and extracts payloads concealed within Discrete Cosine Transform (DCT) coefficients or sample values using tools like Steghide.
- **Metadata Exfiltration**: Audits hidden strings, camera fingerprints, software editing traces, and GPS coordinates.
- **Cryptographic Evidence Fingerprinting**: Computes SHA-256 digests before and after analysis to ensure non-destructive examination.

---

## 🎯 Key Capabilities & Forensic Methodology

| Forensic Stage | Implementation | Purpose |
|---|---|---|
| **Evidence Validation** | Pillow (`PIL.Image.verify`) | Validates authentic image headers; rejects spoofed files (e.g., ASCII text disguised as `.jpg`). |
| **Integrity Assurance** | Python `hashlib.sha256` | Generates a 256-bit cryptographic fingerprint of the original file; preserves chain of custody. |
| **Working Copy Isolation** | `utils/file_manager.py` | Dispatches all inspection and extraction commands against disposable copies, never the evidence original. |
| **Metadata Audit** | `exiftool` JSON interface | Deep extraction of EXIF, GPS, camera manufacturer, and editing software traces. |
| **Embedded Signature Scan** | `binwalk` | Magic-byte scanning to detect concatenated ZIP, RAR, 7Z, ELF, or PE structures. |
| **Steganography Extraction** | `steghide` | Carrier compatibility validation (JPEG/BMP), capacity detection, and authorized passphrase extraction. |
| **Case Documentation** | ReportLab Platypus | Generates court-admissible PDF forensic reports with tool matrices and limitation disclaimers. |
| **Historical Auditing** | SQLite (`history.sqlite`) | Logs previous examinations, timestamps, and findings without retaining sensitive image files. |

---

## 💻 Technology Stack

- **Core Language**: Python 3.10+ (tested on Python 3.13)
- **User Interface**: Streamlit (Forest & Earth 4-Colour Theme: Forest Green `#15370D`, Sage Green `#728E6D`, Muted Gold `#E5CD82`, Soft Butter Yellow `#FFF2B4`)
- **Image Processing**: Pillow
- **Cryptographic Hashing**: `hashlib` (Standard Library)
- **External Forensic Binaries**:
  - **ExifTool**: Multi-format EXIF / XMP / IPTC metadata parser
  - **Binwalk**: Firmware and file structure signature analysis
  - **Steghide**: JPEG and BMP steganographic carrier inspection and payload extraction
- **Report Engine**: ReportLab Platypus PDF Generator
- **Persistence**: SQLite 3 (Standard Library)
- **Testing Framework**: `pytest`

---

## 📁 Architecture & Project Structure

```text
StegAnalyzer/
│
├── app.py                      # Main Streamlit forensic dashboard & interactive workflow
├── requirements.txt            # Python dependencies (Streamlit, Pillow, ReportLab, pytest)
├── README.md                   # Complete system documentation and forensic manual
├── .gitignore                  # Git exclusions for uploads, reports, caches, and database
├── create_test_samples.py      # Automated generator for forensic test samples
│
├── modules/
│   ├── __init__.py
│   ├── file_validator.py       # Pillow-based format identification & file size boundary checks
│   ├── hash_generator.py       # SHA-256 streaming hash calculator and verification
│   ├── metadata_analyzer.py    # ExifTool integration, GPS coordinate and camera parser
│   ├── binwalk_analyzer.py     # Binwalk signature scanning, offset parser & controlled extraction
│   ├── steghide_analyzer.py    # Steghide carrier verification, capacity audit & extraction
│   ├── report_generator.py     # ReportLab PDF report generation with NumberedCanvas
│   └── history_manager.py      # SQLite-backed session & long-term investigation store
│
├── utils/
│   ├── __init__.py
│   ├── config.py               # Central paths, limits, supported carrier formats & theme
│   ├── file_manager.py         # Working copy creation, sanitization & path-traversal guards
│   └── tool_checker.py         # Diagnostic utility to verify ExifTool, Binwalk, and Steghide
│
├── samples/                    # Generated test evidence files (Normal, Appended ZIP, PNG, Spoofed)
├── uploads/                    # Secure local staging for evidence uploads
├── extracted/                  # Isolated sandbox for extracted payloads
├── reports/                    # Generated PDF forensic reports
│
└── tests/
    ├── __init__.py
    ├── test_hash.py            # Unit tests for SHA-256 calculation & chunked streaming
    ├── test_validation.py      # Unit tests for MIME verification & spoofed file rejection
    ├── test_metadata.py        # Unit tests for ExifTool parser & GPS extractor
    ├── test_analysis.py        # Unit tests for Binwalk parser, Steghide guards & ReportLab
    └── test_end_to_end.py      # Full pipeline integration tests (TEST 1 - TEST 6)
```

---

## ⚙️ System Requirements & Tool Installation

StegAnalyzer works on both **Windows** and **Kali Linux**. If an external tool is not installed, StegAnalyzer detects its absence and provides clear configuration warnings rather than crashing or simulating output.

### Windows 10 / 11 Setup

1. **Install Python 3.10+**: Ensure Python is added to your System `PATH`.
2. **Install Python Packages**:
   ```powershell
   pip install -r requirements.txt
   ```
3. **External Tools Configuration**:
   - **ExifTool**:
     - Download the Windows executable from [exiftool.org](https://exiftool.org/).
     - Rename `exiftool(-k).exe` to `exiftool.exe`.
     - Place it in a directory on your `PATH` (e.g., `C:\Windows\System32` or `C:\Tools\`).
   - **Steghide**:
     - Download the Windows binary build from [SourceForge](https://steghide.sourceforge.net/).
     - Extract `steghide.exe` and place it in your `PATH`.
   - **Binwalk**:
     - Can be installed via `pip install binwalk` or run via Windows Subsystem for Linux (WSL).

### Kali Linux / Debian / Ubuntu Setup

On Kali Linux, all forensic tools are natively packaged in apt repositories:

```bash
# 1. Update and install forensic utilities
sudo apt update
sudo apt install -y python3 python3-pip libimage-exiftool-perl binwalk steghide

# 2. Clone the repository
git clone <repository_url>
cd StegAnalyzer

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Launch the application
streamlit run app.py
```

---

## 🚀 Quick Start Guide

### Step 1: Launch the Application
Run the following command from the `StegAnalyzer/` directory:

```bash
streamlit run app.py
```

The Streamlit dashboard will automatically open in your default browser at `http://localhost:8501`.

### Step 2: Investigation Workflow
1. **Stage 1 (Image Upload Dashboard)**:
   - Upload an evidence image (`.jpg`, `.jpeg`, `.png`, or `.bmp`) using the drag-and-drop or browse area.
   - Initial screen displays a clean upload dashboard with zero cluttered empty state cards.
2. **Stage 2 (Active Evidence & Analysis Options)**:
   - Once uploaded, view the **Active Evidence File** card with image preview, format, dimensions, size, and SHA-256 digest in an expandable area.
   - Choose from four interactive forensic operation cards:
     - **Card 1: Steganography Detection**: Inspect carrier capacity and embedding markers using Steghide (JPEG & BMP).
     - **Card 2: Hidden Text Extraction**: Safely extract hidden text messages or files with passphrase input.
     - **Card 3: Metadata Analysis**: Examine camera provenance, date/time, software traces, and GPS coordinates using ExifTool & Pillow.
     - **Card 4: Embedded File Detection**: Identify magic-byte signatures and concatenated archives past EOF using Binwalk.
   - Or click **⚡ ANALYZE ALL OPERATIONS** to execute all applicable tools simultaneously and produce a consolidated multi-vector investigation summary.
3. **Forensic Report Generation**:
   - Click **📄 Download Official PDF Forensic Report** to export publication-quality case documentation.

---

## 🧪 Testing & Verification Suite

StegAnalyzer includes a complete suite of unit and end-to-end integration tests covering all requirements.

### Automated Unit & Integration Tests

Run the full automated test suite using `pytest`:

```bash
python -m pytest tests/ -v
```

Expected output:
```text
StegAnalyzer/tests/test_analysis.py::test_binwalk_output_parser PASSED
StegAnalyzer/tests/test_analysis.py::test_steghide_carrier_format_support PASSED
StegAnalyzer/tests/test_analysis.py::test_steghide_unsupported_format_guard PASSED
StegAnalyzer/tests/test_analysis.py::test_history_manager_crud PASSED
StegAnalyzer/tests/test_analysis.py::test_pdf_report_generation PASSED
StegAnalyzer/tests/test_end_to_end.py::test_e2e_test1_normal_jpeg PASSED
StegAnalyzer/tests/test_end_to_end.py::test_e2e_test4_appended_archive PASSED
StegAnalyzer/tests/test_end_to_end.py::test_e2e_test5_png_unsupported_carrier PASSED
StegAnalyzer/tests/test_end_to_end.py::test_e2e_test6_invalid_file_rejection PASSED
StegAnalyzer/tests/test_end_to_end.py::test_e2e_test3_incorrect_passphrase_safety PASSED
StegAnalyzer/tests/test_hash.py::test_calculate_sha256_from_bytes PASSED
StegAnalyzer/tests/test_hash.py::test_calculate_sha256_file PASSED
StegAnalyzer/tests/test_metadata.py::test_missing_exiftool_handling PASSED
StegAnalyzer/tests/test_metadata.py::test_parse_gps_coordinates PASSED
StegAnalyzer/tests/test_metadata.py::test_get_metadata_summary PASSED
StegAnalyzer/tests/test_validation.py::test_validate_upload_allowed_extensions PASSED
StegAnalyzer/tests/test_validation.py::test_validate_upload_rejected_extensions PASSED
StegAnalyzer/tests/test_validation.py::test_validate_upload_oversized PASSED
StegAnalyzer/tests/test_validation.py::test_validate_image_genuine_jpeg PASSED
StegAnalyzer/tests/test_validation.py::test_validate_image_genuine_png PASSED
StegAnalyzer/tests/test_validation.py::test_validate_image_spoofed_text_file PASSED
============================== 21 passed in 1.29s ==============================
```

### Forensic Test Matrix

To generate test samples matching all project testing criteria, run:

```bash
python create_test_samples.py
```

This generates 5 distinct forensic test samples inside `samples/`:

| Test ID | Test Scenario | Evidence File | Expected Forensic Outcome |
|---|---|---|---|
| **TEST 1** | Normal clean JPEG | `sample1_normal.jpg` | Validation passes; SHA-256 computed; ExifTool/Binwalk display normal headers; Steghide reports no embedded data. |
| **TEST 2** | Image with hidden text | `sample2_normal.bmp` | Steghide recognizes compatible BMP carrier; correct passphrase extracts hidden text payload into preview. |
| **TEST 3** | Incorrect passphrase | Any Steghide image | Extraction rejected gracefully; clear warning displayed; zero application crashes or unhandled exceptions. |
| **TEST 4** | Appended test archive | `sample4_appended_archive.jpg` | Binwalk identifies trailing ZIP signature starting at non-zero offset; flagged as potential anomaly. |
| **TEST 5** | PNG format carrier check | `sample3_format_test.png` | Format flagged as unsupported by Steghide; ExifTool and file structure analysis continue normally. |
| **TEST 6** | Spoofed file validation | `sample5_invalid_spoofed.jpg` | Text file masquerading as `.jpg` is immediately intercepted and rejected by Pillow header verification. |
| **TEST 7** | Missing external tool | System without tool | Diagnostic card displays warning instructions; available tools continue running; zero simulated output. |

---

## 🔒 Digital Forensics & Security Controls

StegAnalyzer incorporates rigorous digital forensics and software security practices:

1. **Evidence Integrity Preservation**:
   - The original uploaded evidence file is stored in `uploads/` with a unique UUID prefix and is **never modified**.
   - Analysis is conducted strictly on working copies in isolated staging locations.
2. **Safe Subprocess Invocation**:
   - Subprocess commands are strictly passed as sanitized argument lists (`["exiftool", "-j", str(path)]`).
   - `shell=True` is completely avoided to prevent command injection.
3. **Path Traversal Protection**:
   - All uploaded filenames are stripped of relative directories (`../`, `..\`) via `utils.file_manager.get_safe_filename()`.
   - Extracted payload files are strictly confined to the `extracted/` sandbox.
4. **Execution Prevention**:
   - Extracted files are treated strictly as passive data artifacts. StegAnalyzer never executes or executes shell commands against extracted payloads.
5. **No Blind Trust of File Extensions**:
   - File extensions are validated for initial filtering, but true format classification is performed using binary magic byte inspection via Pillow.

---

## 📄 Report Generation & Chain of Custody

The generated PDF report contains:
- **Case Identification**: Unique Investigation ID (e.g., `INV-3FA901B2`), analysis timestamp, examiner credentials.
- **Evidence Integrity Table**: Filename, verified format, dimensions, file size in bytes, and the full SHA-256 digest.
- **ExifTool Metadata Findings**: Categorized tables for Camera, GPS Coordinates, Timestamp, and Editing Software.
- **Binwalk Signature Findings**: Detailed decimal and hex offsets alongside signature descriptions.
- **Steghide Carrier Evaluation**: Capacity analysis, embedding observations, and decoded UTF-8 payload previews if extracted.
- **Reproducibility Matrix**: Status and version numbers of all forensic tools present during examination.
- **Methodological Limitations & Disclaimers**: Clarifies that negative findings do not definitively prove the absence of unknown or alternate steganography algorithms.

---

## 🎓 Academic Project Context

- **Course**: 7th Semester B.Tech / B.E. — Cyber Security & Digital Forensics
- **Project Title**: StegAnalyzer – Steganography Detection and Hidden Data Analysis System
- **Authors**: Cyber Security Project Team
- **Admissibility Standard**: Adheres to ISO/IEC 27037 standards for digital evidence handling (identification, collection, acquisition, and preservation).

