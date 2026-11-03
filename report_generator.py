"""
ImageShield — PDF Forensic Report Generator

Generates professional PDF forensic reports using ReportLab,
including image thumbnails, metadata tables, hash values,
ELA results, and forensic disclaimers.
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch, mm
from reportlab.lib.colors import HexColor, black, white
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image as RLImage, PageBreak, HRFlowable,
)
from reportlab.lib import colors

from PIL import Image
import io
import os
from datetime import datetime
from typing import Dict, Any, Optional, List


# ─── Color Palette ──────────────────────────────────────────────────────────────

NAVY = HexColor("#1a1a2e")
DARK_BLUE = HexColor("#16213e")
ACCENT_BLUE = HexColor("#0f3460")
LIGHT_BLUE = HexColor("#4a90d9")
HEADER_BG = HexColor("#1a1a2e")
ROW_ALT = HexColor("#f0f4f8")
BORDER_COLOR = HexColor("#cccccc")


def _create_styles() -> dict:
    """Create custom paragraph styles for the forensic report."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        textColor=NAVY,
        spaceAfter=6,
        alignment=TA_CENTER,
    ))

    styles.add(ParagraphStyle(
        name="ReportSubtitle",
        parent=styles["Normal"],
        fontSize=12,
        textColor=ACCENT_BLUE,
        spaceAfter=20,
        alignment=TA_CENTER,
    ))

    styles.add(ParagraphStyle(
        name="SectionHeader",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=NAVY,
        spaceBefore=16,
        spaceAfter=8,
        borderWidth=1,
        borderColor=LIGHT_BLUE,
        borderPadding=4,
    ))

    styles.add(ParagraphStyle(
        name="BodyText2",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=black,
        alignment=TA_JUSTIFY,
        spaceAfter=6,
    ))

    styles.add(ParagraphStyle(
        name="DisclaimerText",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=HexColor("#666666"),
        alignment=TA_JUSTIFY,
        spaceAfter=4,
    ))

    styles.add(ParagraphStyle(
        name="FindingLabel",
        parent=styles["Normal"],
        fontSize=10,
        textColor=ACCENT_BLUE,
        spaceBefore=4,
        spaceAfter=2,
    ))

    return styles


def _pil_to_reportlab_image(
    pil_image: Image.Image,
    max_width: float = 4.5 * inch,
    max_height: float = 3.5 * inch,
) -> RLImage:
    """
    Convert a PIL Image to a ReportLab Image flowable.

    The image is saved to an in-memory buffer as PNG to preserve
    quality in the PDF report.

    Args:
        pil_image: PIL Image to embed.
        max_width: Maximum width in the PDF.
        max_height: Maximum height in the PDF.

    Returns:
        ReportLab Image flowable sized to fit within bounds.
    """
    buffer = io.BytesIO()
    if pil_image.mode == "RGBA":
        pil_image = pil_image.convert("RGB")
    pil_image.save(buffer, format="PNG")
    buffer.seek(0)

    # Calculate scaled dimensions maintaining aspect ratio
    img_width, img_height = pil_image.size
    aspect = img_width / img_height

    if img_width / max_width > img_height / max_height:
        width = max_width
        height = max_width / aspect
    else:
        height = max_height
        width = max_height * aspect

    return RLImage(buffer, width=width, height=height)


def _build_metadata_table(
    metadata: Dict[str, Any],
    styles: dict,
) -> Table:
    """Build a formatted table of metadata key-value pairs."""
    data = [["Field", "Value"]]

    for key, value in metadata.items():
        # Truncate very long values
        val_str = str(value)
        if len(val_str) > 80:
            val_str = val_str[:77] + "..."

        data.append([
            Paragraph(str(key), styles["BodyText2"]),
            Paragraph(val_str, styles["BodyText2"]),
        ])

    table = Table(data, colWidths=[2.2 * inch, 4.0 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, ROW_ALT]),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 1), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
    ]))

    return table


def generate_report(
    filename: str,
    basic_properties: Dict[str, Any],
    exif_data: Optional[Dict[str, Any]],
    camera_info: Dict[str, str],
    gps_data: Optional[Dict[str, Any]],
    sha256_hash: str,
    comparison_hash: Optional[str],
    hash_match: Optional[bool],
    ela_settings: Optional[Dict[str, Any]],
    ela_stats: Optional[Dict[str, str]],
    findings: List[Dict[str, str]],
    original_image: Optional[Image.Image],
    ela_image: Optional[Image.Image],
    dimension_analysis: Optional[Dict[str, Any]] = None,
    color_channel_stats: Optional[Dict[str, Any]] = None,
    copy_move_result: Optional[str] = None,
) -> bytes:
    """
    Generate a complete PDF forensic report.

    The report is generated entirely in memory and returned as bytes,
    avoiding the need to write temporary files to disk.

    Args:
        filename: Original uploaded filename.
        basic_properties: Basic image property dictionary.
        exif_data: Full EXIF metadata dictionary, or None.
        camera_info: Camera-specific metadata.
        gps_data: GPS metadata dictionary, or None.
        sha256_hash: SHA-256 hash of the original file.
        comparison_hash: SHA-256 hash of comparison file, or None.
        hash_match: Whether hashes matched, or None if not compared.
        ela_settings: ELA quality and scale settings used.
        ela_stats: ELA statistical results.
        findings: Aggregated findings list.
        original_image: Original PIL Image for thumbnail.
        ela_image: ELA result image, or None.
        dimension_analysis: Image dimension analysis results.
        color_channel_stats: Color channel statistics.
        copy_move_result: Copy-move detection result description.

    Returns:
        PDF file content as bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = _create_styles()
    story = []

    # ── Report Header ──────────────────────────────────────────────
    story.append(Paragraph("🛡️ ImageShield", styles["ReportTitle"]))
    story.append(Paragraph(
        "Digital Image Forensics and Integrity Analysis Report",
        styles["ReportSubtitle"],
    ))
    story.append(HRFlowable(
        width="100%", thickness=2, color=LIGHT_BLUE,
        spaceAfter=12, spaceBefore=4,
    ))

    # Report metadata
    now = datetime.now()
    report_meta = {
        "Report Generated": now.strftime("%Y-%m-%d %H:%M:%S"),
        "Original Filename": filename if len(filename) <= 60 else filename[:57] + "...",
        "Analysis Tool": "ImageShield v1.0",
    }
    story.append(_build_metadata_table(report_meta, styles))
    story.append(Spacer(1, 12))

    # ── Image Preview ──────────────────────────────────────────────
    if original_image:
        story.append(Paragraph("1. Image Preview", styles["SectionHeader"]))
        try:
            # Create thumbnail for report
            thumb = original_image.copy()
            thumb.thumbnail((600, 450))
            story.append(_pil_to_reportlab_image(thumb))
            story.append(Spacer(1, 8))
        except Exception:
            story.append(Paragraph(
                "Image thumbnail could not be embedded in this report.",
                styles["BodyText2"],
            ))

    # ── Basic Properties ───────────────────────────────────────────
    story.append(Paragraph("2. Image Properties", styles["SectionHeader"]))
    # Filter out internal-use keys
    display_props = {k: v for k, v in basic_properties.items() if "bytes" not in k.lower() or "File Size" in k}
    story.append(_build_metadata_table(display_props, styles))
    story.append(Spacer(1, 8))

    # ── Metadata & EXIF ────────────────────────────────────────────
    story.append(Paragraph("3. Metadata and EXIF Analysis", styles["SectionHeader"]))

    if camera_info:
        story.append(Paragraph("<b>Camera Information:</b>", styles["BodyText2"]))
        story.append(_build_metadata_table(camera_info, styles))
        story.append(Spacer(1, 6))

    if exif_data:
        story.append(Paragraph(
            f"<b>Full EXIF Data:</b> {len(exif_data)} field(s) found.",
            styles["BodyText2"],
        ))
        # Show up to 25 most relevant fields to keep the report readable
        display_exif = dict(list(exif_data.items())[:25])
        if len(exif_data) > 25:
            display_exif["..."] = f"({len(exif_data) - 25} additional fields not shown)"
        story.append(_build_metadata_table(display_exif, styles))
    else:
        story.append(Paragraph(
            "No EXIF metadata found in this image. This is common for "
            "screenshots, web-downloaded images, and images processed by "
            "applications that strip metadata.",
            styles["BodyText2"],
        ))

    if gps_data:
        story.append(Spacer(1, 6))
        story.append(Paragraph("<b>GPS Data:</b>", styles["BodyText2"]))
        gps_display = {str(k): str(v) for k, v in gps_data.items()}
        story.append(_build_metadata_table(gps_display, styles))

    story.append(Spacer(1, 8))

    # ── SHA-256 Integrity ──────────────────────────────────────────
    story.append(Paragraph("4. SHA-256 Hash Verification", styles["SectionHeader"]))
    hash_info = {"Original File SHA-256": sha256_hash}
    if comparison_hash:
        hash_info["Comparison File SHA-256"] = comparison_hash
        if hash_match is True:
            hash_info["Comparison Result"] = "MATCH — Files are byte-for-byte identical"
        elif hash_match is False:
            hash_info["Comparison Result"] = "NO MATCH — Files differ in at least one byte"
    story.append(_build_metadata_table(hash_info, styles))
    story.append(Spacer(1, 8))

    # ── ELA Results ────────────────────────────────────────────────
    story.append(Paragraph("5. Error Level Analysis (ELA)", styles["SectionHeader"]))

    if ela_settings and ela_stats:
        story.append(Paragraph(
            f"<b>Settings:</b> Quality = {ela_settings.get('quality', 'N/A')}, "
            f"Scale = {ela_settings.get('scale', 'N/A')}",
            styles["BodyText2"],
        ))
        story.append(_build_metadata_table(ela_stats, styles))
        story.append(Spacer(1, 6))

        if ela_image:
            story.append(Paragraph("<b>ELA Visualization:</b>", styles["BodyText2"]))
            try:
                story.append(_pil_to_reportlab_image(ela_image))
            except Exception:
                story.append(Paragraph(
                    "ELA visualization could not be embedded.",
                    styles["BodyText2"],
                ))
    else:
        story.append(Paragraph(
            "ELA was not performed on this image. ELA requires a JPEG input "
            "or optional JPEG conversion.",
            styles["BodyText2"],
        ))

    story.append(Spacer(1, 8))

    # ── Supplementary Analysis ─────────────────────────────────────
    story.append(Paragraph("6. Supplementary Analysis", styles["SectionHeader"]))

    if dimension_analysis:
        story.append(Paragraph("<b>Dimension Analysis:</b>", styles["BodyText2"]))
        dim_display = {str(k): str(v) for k, v in dimension_analysis.items()}
        story.append(_build_metadata_table(dim_display, styles))
        story.append(Spacer(1, 6))

    if color_channel_stats:
        story.append(Paragraph("<b>Color Channel Statistics:</b>", styles["BodyText2"]))
        flat_stats = {}
        for channel, stats in color_channel_stats.items():
            if isinstance(stats, dict):
                for stat_name, stat_val in stats.items():
                    flat_stats[f"{channel} — {stat_name}"] = str(stat_val)
            else:
                flat_stats[channel] = str(stats)
        story.append(_build_metadata_table(flat_stats, styles))
        story.append(Spacer(1, 6))

    if copy_move_result:
        story.append(Paragraph("<b>Copy-Move Detection (Experimental):</b>", styles["BodyText2"]))
        # Clean markdown-style bold for PDF
        clean_text = copy_move_result.replace("**", "")
        story.append(Paragraph(clean_text, styles["BodyText2"]))

    story.append(Spacer(1, 8))

    # ── Findings Summary ───────────────────────────────────────────
    if findings:
        story.append(Paragraph("7. Summary of Findings", styles["SectionHeader"]))
        for finding in findings:
            status_clean = finding.get("status", "").replace("ℹ️", "[INFO]").replace("⚠️", "[NOTE]").replace("❓", "[?]").replace("🚫", "[N/A]")
            story.append(Paragraph(
                f"<b>{finding.get('category', 'Unknown')}:</b> {status_clean}",
                styles["FindingLabel"],
            ))
            story.append(Paragraph(finding.get("detail", ""), styles["BodyText2"]))
            story.append(Spacer(1, 4))

    # ── Limitations & Disclaimer ───────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("8. Limitations and Disclaimer", styles["SectionHeader"]))
    story.append(HRFlowable(
        width="100%", thickness=1, color=BORDER_COLOR,
        spaceAfter=8, spaceBefore=4,
    ))

    disclaimers = [
        "This report was generated by ImageShield, an automated digital "
        "image forensics tool. The analyses performed are preliminary "
        "screening techniques and are NOT a substitute for expert forensic "
        "examination.",

        "Error Level Analysis (ELA) is a heuristic method with known "
        "limitations. Results can be affected by JPEG compression history, "
        "image content, resizing, color adjustments, and multiple re-saves. "
        "ELA alone cannot definitively prove or disprove image manipulation.",

        "Metadata (EXIF data) can be added, modified, stripped, or fabricated. "
        "The presence or absence of specific metadata fields does not "
        "constitute proof of authenticity or manipulation.",

        "SHA-256 hash comparison verifies byte-level file identity. Different "
        "hashes indicate the files are not identical but do not specify what "
        "changed or whether visual content was affected.",

        "Copy-move detection (if performed) uses simplified feature matching "
        "and has a significant false-positive rate. Results are experimental "
        "and require manual verification.",

        "No automated tool can conclusively authenticate or debunk a digital "
        "image. Findings in this report should be interpreted by qualified "
        "personnel in the context of the specific investigation.",
    ]

    for disclaimer in disclaimers:
        story.append(Paragraph(f"• {disclaimer}", styles["DisclaimerText"]))
        story.append(Spacer(1, 3))

    story.append(Spacer(1, 16))
    story.append(HRFlowable(
        width="100%", thickness=1, color=BORDER_COLOR,
        spaceAfter=8, spaceBefore=4,
    ))
    story.append(Paragraph(
        f"Report generated on {now.strftime('%B %d, %Y at %H:%M:%S')} "
        f"by ImageShield v1.0 — Digital Image Forensics and Integrity Analysis",
        styles["DisclaimerText"],
    ))

    # Build the PDF
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()

    return pdf_bytes
