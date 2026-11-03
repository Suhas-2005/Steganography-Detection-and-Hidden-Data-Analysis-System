"""
StegAnalyzer — PDF Forensic Report Generation.

Generates court- and academic-grade digital forensics reports in PDF format
using ReportLab Platypus. Contains complete provenance, integrity hashes,
tool execution findings, extraction records, and limitations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from utils.config import APP_NAME, APP_SUBTITLE, REPORTS_DIR, VERSION


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and render total page count."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(
                54,
                11 * inch - 36,
                f"{APP_NAME} v{VERSION} — Digital Forensic Investigation Report",
            )
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 11 * inch - 42, 8.5 * inch - 54, 11 * inch - 42)

        # Footer
        footer_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * inch - 54, 36, footer_text)
        confidential_text = "CONFIDENTIAL // LAW ENFORCEMENT & FORENSIC DISCOVERY USE"
        self.drawString(54, 36, confidential_text)
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 46, 8.5 * inch - 54, 46)

        self.restoreState()


def generate_forensic_report(analysis_data: dict[str, Any], output_path: Path | None = None) -> Path:
    """Generate a comprehensive PDF forensic investigation report.

    Parameters
    ----------
    analysis_data : dict
        Investigation dictionary containing metadata, binwalk, steghide, hash, etc.
    output_path : Path, optional
        Target PDF file path. If None, saved in reports/ directory.

    Returns
    -------
    Path
        Path to the generated PDF document.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    inv_id = analysis_data.get("investigation_id", "INVESTIGATION")
    if not output_path:
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = REPORTS_DIR / f"Forensic_Report_{inv_id}_{timestamp_str}.pdf"

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom typography
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
        spaceAfter=12,
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#15370D"),
        spaceBefore=14,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b"),
    )
    body_bold = ParagraphStyle(
        "ReportBodyBold",
        parent=body_style,
        fontName="Helvetica-Bold",
    )
    code_style = ParagraphStyle(
        "ReportCode",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0f172a"),
    )
    table_cell = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1e293b"),
    )
    table_cell_bold = ParagraphStyle(
        "TableCellBold",
        parent=table_cell,
        fontName="Helvetica-Bold",
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph(f"{APP_NAME} FORENSIC REPORT", title_style))
    story.append(Paragraph(f"{APP_SUBTITLE} — Evidence Examination & Analysis", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#15370D"), spaceAfter=12))

    # 2. Executive Metadata Box
    exec_data = [
        [
            Paragraph("Investigation ID:", table_cell_bold),
            Paragraph(inv_id, table_cell),
            Paragraph("Date / Time:", table_cell_bold),
            Paragraph(analysis_data.get("timestamp", "N/A"), table_cell),
        ],
        [
            Paragraph("Examiner:", table_cell_bold),
            Paragraph("StegAnalyzer Automated Suite", table_cell),
            Paragraph("Overall Status:", table_cell_bold),
            Paragraph(f"<b>{analysis_data.get('overall_status', 'Analysis Completed')}</b>", table_cell),
        ],
    ]
    exec_table = Table(exec_data, colWidths=[100, 150, 100, 154])
    exec_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(exec_table)
    story.append(Spacer(1, 12))

    # 3. Section A: Evidence File Information & Integrity Hash
    story.append(Paragraph("A. EVIDENCE IDENTIFICATION & INTEGRITY", section_heading))
    file_info = [
        [Paragraph("Original Filename", table_cell_bold), Paragraph(analysis_data.get("filename", "N/A"), table_cell)],
        [Paragraph("Detected File Format", table_cell_bold), Paragraph(str(analysis_data.get("file_format", "N/A")), table_cell)],
        [Paragraph("File Size", table_cell_bold), Paragraph(str(analysis_data.get("file_size_str", "N/A")), table_cell)],
        [Paragraph("Image Dimensions", table_cell_bold), Paragraph(str(analysis_data.get("dimensions", "N/A")), table_cell)],
        [Paragraph("Color Mode", table_cell_bold), Paragraph(str(analysis_data.get("color_mode", "N/A")), table_cell)],
        [
            Paragraph("SHA-256 Digest", table_cell_bold),
            Paragraph(f"<code>{analysis_data.get('sha256', 'N/A')}</code>", code_style),
        ],
    ]
    file_table = Table(file_info, colWidths=[140, 364])
    file_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(file_table)
    story.append(Spacer(1, 10))

    # 4. Section B: Metadata Extraction (ExifTool)
    story.append(Paragraph("B. METADATA ANALYSIS (EXIFTOOL)", section_heading))
    meta_results = analysis_data.get("metadata_results", {})
    if not meta_results.get("tool_available", False):
        story.append(Paragraph("<i>ExifTool was not installed on the system PATH during this examination. Metadata extraction could not be executed.</i>", body_style))
    elif not meta_results.get("metadata"):
        story.append(Paragraph("<i>No standard EXIF, XMP, or IPTC metadata found in this image file.</i>", body_style))
    else:
        key_findings = meta_results.get("key_findings", {})
        meta_rows = [[Paragraph("Category", table_cell_bold), Paragraph("Tag", table_cell_bold), Paragraph("Extracted Value", table_cell_bold)]]
        
        for category, tags in key_findings.items():
            for k, v in tags.items():
                val_str = str(v)
                if len(val_str) > 70:
                    val_str = val_str[:67] + "..."
                meta_rows.append([
                    Paragraph(category, table_cell),
                    Paragraph(k, table_cell_bold),
                    Paragraph(val_str, table_cell),
                ])

        if len(meta_rows) > 1:
            meta_table = Table(meta_rows, colWidths=[110, 130, 264])
            meta_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(meta_table)
        else:
            story.append(Paragraph("<i>Only generic format headers were reported; no notable EXIF metadata present.</i>", body_style))
    story.append(Spacer(1, 10))

    # 5. Section C: Embedded Signatures (Binwalk)
    story.append(Paragraph("C. EMBEDDED FILE SIGNATURE ANALYSIS (BINWALK)", section_heading))
    binwalk_results = analysis_data.get("binwalk_results", {})
    if not binwalk_results.get("tool_available", False):
        story.append(Paragraph("<i>Binwalk was not available on the examination system. Signature analysis could not be performed.</i>", body_style))
    else:
        signatures = binwalk_results.get("signatures", [])
        story.append(Paragraph(f"<b>Summary:</b> {binwalk_results.get('summary', 'Scan executed.')}", body_style))
        story.append(Spacer(1, 4))
        
        if signatures:
            sig_rows = [[Paragraph("Decimal Offset", table_cell_bold), Paragraph("Hex Offset", table_cell_bold), Paragraph("Signature Description", table_cell_bold)]]
            for s in signatures:
                sig_rows.append([
                    Paragraph(str(s.get("offset_dec", "")), table_cell),
                    Paragraph(str(s.get("offset_hex", "")), table_cell),
                    Paragraph(str(s.get("description", "")), table_cell),
                ])
            sig_table = Table(sig_rows, colWidths=[90, 80, 334])
            sig_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(sig_table)
        else:
            story.append(Paragraph("<i>No embedded signatures or concatenated structures reported by Binwalk.</i>", body_style))
    story.append(Spacer(1, 10))

    # 6. Section D: Steganography Analysis (Steghide)
    story.append(Paragraph("D. STEGANOGRAPHY ANALYSIS (STEGHIDE)", section_heading))
    steghide_results = analysis_data.get("steghide_results", {})
    if not steghide_results.get("format_supported", True):
        story.append(Paragraph(
            f"<b>Carrier Compatibility:</b> The evidence file is not a supported Steghide carrier format. "
            f"Steghide operates specifically on JPEG and BMP images. PNG files are not compatible with Steghide.",
            body_style,
        ))
    elif not steghide_results.get("tool_available", False):
        story.append(Paragraph("<i>Steghide is not installed on the system PATH. Steganography inspection was skipped.</i>", body_style))
    else:
        story.append(Paragraph(f"<b>Inspection Observation:</b> {steghide_results.get('explanation', 'Inspection attempted.')}", body_style))
        if steghide_results.get("capacity"):
            story.append(Paragraph(f"<b>Reported Embedding Capacity:</b> {steghide_results.get('capacity')}", body_style))

        # Extraction details
        extract_res = analysis_data.get("extraction_results", {})
        if extract_res:
            story.append(Spacer(1, 4))
            if extract_res.get("success"):
                story.append(Paragraph("<b>Extraction Status: SUCCESSFUL EXTRACTION</b>", body_bold))
                story.append(Paragraph(f"Payload Size: {extract_res.get('extracted_file_size')} bytes", body_style))
                if extract_res.get("is_text") and extract_res.get("extracted_text"):
                    story.append(Paragraph("<b>Extracted Text Content (Decoded UTF-8):</b>", body_bold))
                    story.append(Paragraph(f"<code>{extract_res.get('extracted_text')}</code>", code_style))
            else:
                story.append(Paragraph(f"<b>Extraction Status:</b> {extract_res.get('message', 'Unsuccessful')}", body_style))
    story.append(Spacer(1, 10))

    # 7. Section E: Investigation Summary & Findings
    story.append(Paragraph("E. OVERALL FORENSIC FINDINGS & CONCLUSION", section_heading))
    summary_text = analysis_data.get("overall_summary", "Forensic examination completed.")
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 8))

    # 8. Section F: Tool Availability & Verification
    story.append(Paragraph("F. FORENSIC TOOL MATRIX & REPRODUCIBILITY", section_heading))
    tools_info = analysis_data.get("tools_status", {})
    tool_rows = [[Paragraph("Tool Name", table_cell_bold), Paragraph("Status", table_cell_bold), Paragraph("Version / Environment", table_cell_bold)]]
    for name, info in tools_info.items():
        status_str = "Available" if info.get("available") else "Not Installed"
        ver_str = str(info.get("version") or info.get("path") or "N/A")
        tool_rows.append([
            Paragraph(name.capitalize(), table_cell),
            Paragraph(status_str, table_cell_bold),
            Paragraph(ver_str, table_cell),
        ])
    tool_table = Table(tool_rows, colWidths=[120, 100, 284])
    tool_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(tool_table)
    story.append(Spacer(1, 10))

    # 9. Section G: Forensic Limitations & Disclaimer
    story.append(Paragraph("G. METHODOLOGICAL LIMITATIONS & DISCLAIMER", section_heading))
    disclaimer = (
        "1. Negative findings with Steghide do not prove that an image contains no concealed data; "
        "other steganographic algorithms (e.g., LSB, F5, OutGuess, OpenPuff) may have been employed.<br/>"
        "2. Binwalk signature detection relies on known magic byte offsets; encrypted or high-entropy "
        "raw payloads without file headers may not produce signature matches.<br/>"
        "3. File integrity was preserved by performing all extraction and inspection tasks on isolated "
        "working copies. The original SHA-256 evidence fingerprint remains unchanged."
    )
    story.append(Paragraph(disclaimer, table_cell))

    # Build the document
    doc.build(story, canvasmaker=NumberedCanvas)
    return output_path

