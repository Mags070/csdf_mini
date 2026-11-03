"""
ImageShield — Digital Image Forensics and Integrity Analysis
Main Streamlit Application

This is the entry point for the ImageShield web application.
Run with: streamlit run app.py
"""

import streamlit as st
from PIL import Image
import io
import numpy as np
from datetime import datetime

# ─── Import ImageShield modules ─────────────────────────────────────────────────
from metadata_analyzer import (
    get_basic_properties,
    extract_exif_data,
    extract_gps_data,
    convert_gps_to_decimal,
    get_camera_info,
    get_forensic_summary,
)
from hash_analyzer import compute_sha256, compare_hashes, get_hash_info
from ela_analyzer import (
    perform_ela,
    compute_ela_statistics,
    is_jpeg_compatible,
    convert_and_analyze,
    get_ela_explanation,
)
from forensic_analyzer import (
    generate_grayscale,
    detect_edges,
    analyze_color_channels,
    detect_copy_move,
    get_image_dimensions_analysis,
    aggregate_findings,
    STATUS_INFO,
    STATUS_ANOMALY,
    STATUS_INCONCLUSIVE,
    STATUS_UNAVAILABLE,
)
from report_generator import generate_report


# ─── Page Configuration ─────────────────────────────────────────────────────────

st.set_page_config(
    page_title="ImageShield — Digital Image Forensics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Maximum upload size in MB
MAX_UPLOAD_SIZE_MB = 50


# ─── Custom CSS for Dark Forensic Theme ─────────────────────────────────────────

st.markdown("""
<style>
    /* ── Main Theme ──────────────────────────────────────────────── */
    .stApp {
        background-color: #0e1117;
    }

    /* ── Header Styling ──────────────────────────────────────────── */
    .main-header {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
        padding: 2rem 2rem 1.5rem 2rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        border: 1px solid #1e3a5f;
        text-align: center;
    }
    .main-header h1 {
        color: #e0e7ff;
        font-size: 2.4rem;
        margin: 0;
        font-weight: 700;
        letter-spacing: 1px;
    }
    .main-header p {
        color: #94a3b8;
        font-size: 1.05rem;
        margin-top: 0.4rem;
        margin-bottom: 0;
    }

    /* ── Metric Cards ────────────────────────────────────────────── */
    .metric-card {
        background: linear-gradient(135deg, #1e293b, #1a1a2e);
        border: 1px solid #2d3748;
        border-radius: 10px;
        padding: 1.1rem;
        text-align: center;
        transition: border-color 0.2s;
    }
    .metric-card:hover {
        border-color: #4a90d9;
    }
    .metric-card .label {
        color: #94a3b8;
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 0.3rem;
    }
    .metric-card .value {
        color: #e0e7ff;
        font-size: 1.25rem;
        font-weight: 600;
    }

    /* ── Section Headers ─────────────────────────────────────────── */
    .section-header {
        color: #e0e7ff;
        font-size: 1.15rem;
        font-weight: 600;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid #4a90d9;
        margin-bottom: 1rem;
        margin-top: 0.5rem;
    }

    /* ── Status Badges ───────────────────────────────────────────── */
    .status-info {
        background-color: #1e3a5f;
        color: #93c5fd;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.85rem;
        display: inline-block;
    }
    .status-anomaly {
        background-color: #78350f;
        color: #fcd34d;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.85rem;
        display: inline-block;
    }
    .status-inconclusive {
        background-color: #3f3f46;
        color: #d4d4d8;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.85rem;
        display: inline-block;
    }
    .status-unavailable {
        background-color: #1c1c1c;
        color: #737373;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.85rem;
        display: inline-block;
    }

    /* ── Hash Display ────────────────────────────────────────────── */
    .hash-display {
        background: #1a1a2e;
        border: 1px solid #2d3748;
        border-radius: 8px;
        padding: 0.8rem 1rem;
        font-family: 'Courier New', monospace;
        font-size: 0.85rem;
        color: #93c5fd;
        word-break: break-all;
        margin: 0.5rem 0;
    }

    /* ── Info Box ─────────────────────────────────────────────────── */
    .info-box {
        background: #0f1b2d;
        border-left: 4px solid #4a90d9;
        border-radius: 0 8px 8px 0;
        padding: 1rem 1.2rem;
        margin: 0.75rem 0;
        color: #cbd5e1;
        font-size: 0.92rem;
    }

    /* ── Sidebar ─────────────────────────────────────────────────── */
    section[data-testid="stSidebar"] {
        background-color: #111827;
        border-right: 1px solid #1e3a5f;
    }
    section[data-testid="stSidebar"] .stMarkdown h1,
    section[data-testid="stSidebar"] .stMarkdown h2,
    section[data-testid="stSidebar"] .stMarkdown h3 {
        color: #e0e7ff;
    }

    /* ── Tab Styling ─────────────────────────────────────────────── */
    .stTabs [data-baseweb="tab-list"] {
        gap: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #1a1a2e;
        border-radius: 6px 6px 0 0;
        color: #94a3b8;
        padding: 0.5rem 1.2rem;
        border: 1px solid #2d3748;
        border-bottom: none;
    }
    .stTabs [aria-selected="true"] {
        background-color: #0f3460 !important;
        color: #e0e7ff !important;
        border-color: #4a90d9 !important;
    }

    /* ── Expander ─────────────────────────────────────────────────── */
    .streamlit-expanderHeader {
        background-color: #1a1a2e;
        color: #e0e7ff;
        border-radius: 8px;
    }

    /* ── Footer ───────────────────────────────────────────────────── */
    .footer {
        text-align: center;
        color: #4a5568;
        font-size: 0.8rem;
        padding: 2rem 0 1rem 0;
        border-top: 1px solid #1e293b;
        margin-top: 2rem;
    }
</style>
""", unsafe_allow_html=True)


# ─── Helper Functions ────────────────────────────────────────────────────────────

def render_header():
    """Render the application header."""
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ ImageShield</h1>
        <p>Digital Image Forensics and Integrity Analysis</p>
    </div>
    """, unsafe_allow_html=True)


def render_metric_card(label: str, value: str):
    """Render a styled metric card."""
    st.markdown(f"""
    <div class="metric-card">
        <div class="label">{label}</div>
        <div class="value">{value}</div>
    </div>
    """, unsafe_allow_html=True)


def render_status_badge(status: str):
    """Render a color-coded status badge."""
    if STATUS_ANOMALY in status or "Anomaly" in status:
        css_class = "status-anomaly"
    elif STATUS_INCONCLUSIVE in status or "Inconclusive" in status:
        css_class = "status-inconclusive"
    elif STATUS_UNAVAILABLE in status or "Unavailable" in status:
        css_class = "status-unavailable"
    else:
        css_class = "status-info"

    st.markdown(f'<span class="{css_class}">{status}</span>', unsafe_allow_html=True)


def validate_upload(uploaded_file) -> tuple:
    """
    Validate the uploaded file and return (is_valid, file_bytes, image, error_msg).

    Checks file size, attempts to open as an image, and verifies the
    format is supported.
    """
    try:
        file_bytes = uploaded_file.read()
        uploaded_file.seek(0)  # Reset for potential re-reads

        # Check file size
        size_mb = len(file_bytes) / (1024 * 1024)
        if size_mb > MAX_UPLOAD_SIZE_MB:
            return (False, file_bytes, None,
                    f"File too large ({size_mb:.1f} MB). Maximum is {MAX_UPLOAD_SIZE_MB} MB.")

        # Try to open as an image
        image = Image.open(io.BytesIO(file_bytes))
        image.load()  # Force full decode to catch corrupted files

        # Check format
        fmt = image.format
        if fmt and fmt.upper() not in ("JPEG", "JPG", "PNG"):
            return (False, file_bytes, None,
                    f"Unsupported format: {fmt}. Please upload JPEG or PNG images.")

        return (True, file_bytes, image, None)

    except Exception as e:
        return (False, None, None,
                f"Could not open the file as an image. It may be corrupted or "
                f"in an unsupported format. Error: {str(e)}")


# ─── Sidebar ─────────────────────────────────────────────────────────────────────

def render_sidebar():
    """Render the sidebar with upload controls and settings."""
    with st.sidebar:
        st.markdown("## 🛡️ ImageShield")
        st.markdown("---")

        st.markdown("### 📤 Upload Image")
        uploaded_file = st.file_uploader(
            "Choose an image to analyze",
            type=["jpg", "jpeg", "png"],
            key="primary_upload",
            help="Upload a JPG, JPEG, or PNG image for forensic analysis.",
        )

        st.markdown("---")

        st.markdown("### ⚙️ ELA Settings")
        ela_quality = st.slider(
            "JPEG Recompression Quality",
            min_value=50,
            max_value=99,
            value=90,
            step=1,
            help="Quality level for ELA recompression. Lower values amplify differences.",
        )
        ela_scale = st.slider(
            "Visualization Scale",
            min_value=1,
            max_value=50,
            value=15,
            step=1,
            help="Multiplier for the ELA difference image. Higher values make differences more visible.",
        )

        st.markdown("---")

        st.markdown("### 🔍 Hash Comparison")
        comparison_file = st.file_uploader(
            "Upload a second image for hash comparison",
            type=["jpg", "jpeg", "png"],
            key="comparison_upload",
            help="Upload a second image to compare SHA-256 hashes.",
        )

        st.markdown("---")

        st.markdown("### 📋 About")
        st.markdown(
            '<div class="info-box">'
            "ImageShield is a digital forensics tool for preliminary "
            "image analysis. It does not make definitive authenticity "
            "claims. All findings require professional interpretation."
            "</div>",
            unsafe_allow_html=True,
        )

        return uploaded_file, ela_quality, ela_scale, comparison_file


# ─── Main Application ───────────────────────────────────────────────────────────

def main():
    """Main application entry point."""
    render_header()

    # Sidebar controls
    uploaded_file, ela_quality, ela_scale, comparison_file = render_sidebar()

    if uploaded_file is None:
        # Landing page
        st.markdown("""
        <div class="info-box">
            <strong>Welcome to ImageShield!</strong><br><br>
            Upload a digital image using the sidebar to begin forensic analysis.
            ImageShield will examine metadata, verify file integrity, perform
            error level analysis, and generate a comprehensive forensic report.<br><br>
            <strong>Supported formats:</strong> JPEG, JPG, PNG<br>
            <strong>Maximum file size:</strong> 50 MB
        </div>
        """, unsafe_allow_html=True)

        # Feature overview
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            render_metric_card("📋 Metadata", "EXIF Analysis")
        with col2:
            render_metric_card("🔐 Integrity", "SHA-256 Hash")
        with col3:
            render_metric_card("🔬 ELA", "Error Level Analysis")
        with col4:
            render_metric_card("📄 Report", "PDF Generation")

        st.markdown("""
        <div class="footer">
            ImageShield v1.0 — Digital Image Forensics and Integrity Analysis<br>
            For educational and preliminary forensic screening purposes only.
        </div>
        """, unsafe_allow_html=True)
        return

    # ─── Validate Upload ─────────────────────────────────────────────────────
    is_valid, file_bytes, image, error_msg = validate_upload(uploaded_file)

    if not is_valid:
        st.error(f"❌ **Upload Error:** {error_msg}")
        return

    filename = uploaded_file.name

    # ─── Run Analyses ────────────────────────────────────────────────────────
    # These are computed once and cached via Streamlit's execution model

    # Basic properties
    basic_props = get_basic_properties(image, file_bytes)

    # Metadata / EXIF
    exif_data = extract_exif_data(image)
    gps_data = extract_gps_data(image)
    camera_info = get_camera_info(exif_data)
    metadata_findings = get_forensic_summary(exif_data, gps_data)

    # SHA-256 hash
    sha256_hash = compute_sha256(file_bytes)

    # Hash comparison
    comparison_hash = None
    hash_match = None
    if comparison_file is not None:
        comp_bytes = comparison_file.read()
        comparison_file.seek(0)
        comparison_hash = compute_sha256(comp_bytes)
        hash_match, _ = compare_hashes(sha256_hash, comparison_hash)

    # JPEG compatibility check
    jpeg_ok, jpeg_msg = is_jpeg_compatible(image, file_bytes)

    # ELA
    ela_image = None
    ela_diff = None
    ela_stats = None
    ela_performed = False

    # Dimension & channel analysis
    dim_analysis = get_image_dimensions_analysis(image)
    color_stats = analyze_color_channels(image)

    # ─── Dashboard Tabs ──────────────────────────────────────────────────────
    tab_overview, tab_metadata, tab_integrity, tab_ela, tab_analysis, tab_report = st.tabs([
        "📊 Overview",
        "📋 Metadata",
        "🔐 Integrity",
        "🔬 ELA",
        "🔍 Analysis",
        "📄 Report",
    ])

    # ─── Tab: Overview ───────────────────────────────────────────────────────
    with tab_overview:
        st.markdown('<div class="section-header">Image Overview</div>', unsafe_allow_html=True)

        col_img, col_info = st.columns([1, 1])

        with col_img:
            st.image(image, caption=f"📷 {filename}", use_container_width=True)

        with col_info:
            # Metric cards in grid
            m1, m2 = st.columns(2)
            with m1:
                render_metric_card("Format", basic_props.get("Filename Format", "—"))
                st.markdown("")
                render_metric_card("Width", f"{basic_props.get('Width (px)', '—')} px")
                st.markdown("")
                render_metric_card("Color Mode", basic_props.get("Color Mode", "—"))
            with m2:
                render_metric_card("File Size", basic_props.get("File Size", "—"))
                st.markdown("")
                render_metric_card("Height", f"{basic_props.get('Height (px)', '—')} px")
                st.markdown("")
                render_metric_card("Resolution", basic_props.get("Megapixels", "—"))

        st.markdown("")
        st.markdown('<div class="section-header">SHA-256 Hash</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="hash-display">{sha256_hash}</div>', unsafe_allow_html=True)

        # Quick findings summary
        if camera_info:
            st.markdown("")
            st.markdown('<div class="section-header">Camera Information</div>', unsafe_allow_html=True)
            st.table(camera_info)

    # ─── Tab: Metadata ──────────────────────────────────────────────────────
    with tab_metadata:
        st.markdown('<div class="section-header">Metadata and EXIF Analysis</div>', unsafe_allow_html=True)

        st.info(
            "📌 **Note:** Metadata can be modified, stripped, or fabricated. "
            "Its presence or absence does not conclusively prove authenticity "
            "or manipulation."
        )

        # Basic properties table
        with st.expander("📐 Basic Image Properties", expanded=True):
            display_props = {k: v for k, v in basic_props.items() if "bytes" not in k.lower()}
            st.table(display_props)

        # EXIF data
        with st.expander("📷 EXIF Metadata", expanded=True):
            if exif_data:
                st.success(f"✅ EXIF metadata found — **{len(exif_data)} field(s)**")
                st.dataframe(
                    data={"Field": list(exif_data.keys()), "Value": [str(v) for v in exif_data.values()]},
                    use_container_width=True,
                    height=400,
                )
            else:
                st.warning(
                    "⚠️ No EXIF metadata found. This is common for screenshots, "
                    "web images, and images processed by applications that strip metadata."
                )

        # Camera info
        if camera_info:
            with st.expander("📸 Camera Information", expanded=True):
                st.table(camera_info)

        # GPS data
        with st.expander("📍 GPS Location Data", expanded=False):
            if gps_data:
                st.success("✅ GPS data found in image metadata.")
                st.table({str(k): str(v) for k, v in gps_data.items()})

                coords = convert_gps_to_decimal(gps_data)
                if coords:
                    st.info(f"📍 Decimal coordinates: {coords[0]:.6f}, {coords[1]:.6f}")
                    st.warning(
                        "⚠️ GPS data can be spoofed or modified. Coordinates should be "
                        "verified independently."
                    )
            else:
                st.info("ℹ️ No GPS location data found in this image.")

        # Forensic metadata summary
        with st.expander("🔎 Metadata Forensic Summary", expanded=True):
            for key, finding in metadata_findings.items():
                st.markdown(f"**{key}:**")
                st.markdown(finding)
                st.markdown("---")

    # ─── Tab: Integrity ──────────────────────────────────────────────────────
    with tab_integrity:
        st.markdown('<div class="section-header">SHA-256 Hash Verification</div>', unsafe_allow_html=True)

        with st.expander("📚 What is SHA-256?", expanded=False):
            st.markdown(get_hash_info())

        st.markdown("#### Original File Hash")
        st.markdown(f'<div class="hash-display">{sha256_hash}</div>', unsafe_allow_html=True)
        st.caption(f"File: {filename}")

        st.markdown("---")

        st.markdown("#### Hash Comparison")

        if comparison_file is not None:
            st.markdown(f"**Comparison file:** {comparison_file.name}")
            st.markdown(f'<div class="hash-display">{comparison_hash}</div>', unsafe_allow_html=True)

            _, explanation = compare_hashes(sha256_hash, comparison_hash)
            if hash_match:
                st.success(explanation)
            else:
                st.warning(explanation)
        else:
            st.info(
                "ℹ️ Upload a second image in the sidebar to compare hashes. "
                "This allows you to verify if two files are byte-for-byte identical."
            )

    # ─── Tab: ELA ────────────────────────────────────────────────────────────
    with tab_ela:
        st.markdown('<div class="section-header">Error Level Analysis (ELA)</div>', unsafe_allow_html=True)

        with st.expander("📚 Understanding ELA", expanded=False):
            st.markdown(get_ela_explanation())

        if jpeg_ok:
            st.info(f"ℹ️ {jpeg_msg}")

            # Perform ELA
            try:
                with st.spinner("Performing Error Level Analysis..."):
                    ela_image, ela_diff = perform_ela(image, quality=ela_quality, scale=ela_scale)
                    ela_stats = compute_ela_statistics(ela_diff)
                    ela_performed = True

                # Display results side by side
                col_orig, col_ela = st.columns(2)
                with col_orig:
                    st.markdown("**Original Image**")
                    st.image(image, use_container_width=True)
                with col_ela:
                    st.markdown("**ELA Visualization**")
                    st.image(ela_image, use_container_width=True)

                # ELA statistics
                st.markdown("")
                st.markdown("#### ELA Statistics")
                stat_cols = st.columns(5)
                stat_items = list(ela_stats.items())
                for i, (key, val) in enumerate(stat_items):
                    with stat_cols[i]:
                        render_metric_card(key.replace("Error Level", "").strip() or key, val)

                st.markdown("")
                st.markdown(f"**Settings:** Quality = {ela_quality}, Scale = {ela_scale}")

                st.warning(
                    "⚠️ **Interpretation Guide:** Brighter regions indicate higher error "
                    "levels. Uniform brightness suggests consistent compression history. "
                    "Regions with distinctly different brightness *may* have been edited, "
                    "but can also be caused by image content, edges, or compression artifacts. "
                    "ELA alone cannot prove manipulation."
                )

            except Exception as e:
                st.error(f"❌ ELA analysis failed: {str(e)}")

        else:
            st.warning(f"⚠️ {jpeg_msg}")

            # Offer JPEG conversion for PNG
            if image.format and image.format.upper() == "PNG":
                st.markdown("---")
                if st.button("🔄 Analyze JPEG-Converted Copy", help="Convert PNG to JPEG and perform ELA"):
                    try:
                        with st.spinner("Converting to JPEG and performing ELA..."):
                            ela_image, ela_diff = convert_and_analyze(
                                image, quality=ela_quality, scale=ela_scale,
                            )
                            ela_stats = compute_ela_statistics(ela_diff)
                            ela_performed = True

                        st.info(
                            "ℹ️ **Note:** This ELA is performed on a JPEG-converted copy "
                            "of the original PNG. Results reflect the conversion process "
                            "and may not reveal manipulations in the original PNG file."
                        )

                        col_orig, col_ela = st.columns(2)
                        with col_orig:
                            st.markdown("**Original PNG Image**")
                            st.image(image, use_container_width=True)
                        with col_ela:
                            st.markdown("**ELA of JPEG-Converted Copy**")
                            st.image(ela_image, use_container_width=True)

                        st.markdown("#### ELA Statistics (Converted Copy)")
                        stat_cols = st.columns(5)
                        stat_items = list(ela_stats.items())
                        for i, (key, val) in enumerate(stat_items):
                            with stat_cols[i]:
                                render_metric_card(key.replace("Error Level", "").strip() or key, val)

                    except Exception as e:
                        st.error(f"❌ Converted ELA analysis failed: {str(e)}")

    # ─── Tab: Analysis ───────────────────────────────────────────────────────
    with tab_analysis:
        st.markdown('<div class="section-header">Image Consistency Analysis</div>', unsafe_allow_html=True)

        st.info(
            "📌 These supplementary analyses provide additional visual perspectives. "
            "They are screening tools and may produce false positives or miss subtle manipulations."
        )

        # Dimension analysis
        with st.expander("📐 Dimension and Channel Analysis", expanded=True):
            d_col1, d_col2 = st.columns(2)
            with d_col1:
                st.markdown("**Dimensions**")
                st.table(dim_analysis)
            with d_col2:
                st.markdown("**Color Channel Statistics**")
                if isinstance(color_stats, dict) and "Note" not in color_stats:
                    for ch_name, ch_stats in color_stats.items():
                        if isinstance(ch_stats, dict):
                            st.markdown(f"**{ch_name} Channel**")
                            st.table(ch_stats)
                else:
                    st.info("Single-channel (grayscale) image.")

        # Grayscale and Edge Detection
        with st.expander("🖼️ Grayscale and Edge Detection", expanded=True):
            try:
                col_gray, col_edge = st.columns(2)
                with col_gray:
                    st.markdown("**Grayscale Conversion**")
                    gray_img = generate_grayscale(image)
                    st.image(gray_img, use_container_width=True)

                with col_edge:
                    st.markdown("**Canny Edge Detection**")
                    edge_img = detect_edges(image)
                    st.image(edge_img, use_container_width=True)

                st.caption(
                    "Edge detection highlights boundaries in the image. Inconsistent "
                    "edge patterns near edited regions may be notable, but edges are "
                    "naturally affected by image content and compression."
                )
            except Exception as e:
                st.error(f"❌ Visualization error: {str(e)}")

        # Copy-Move Detection (Experimental)
        with st.expander("🧪 Copy-Move Detection (Experimental)", expanded=False):
            st.warning(
                "⚠️ **Experimental Feature:** This uses simplified ORB feature matching "
                "and has a high false-positive rate on images with repetitive patterns, "
                "textures, or symmetrical structures. Results are for educational purposes."
            )

            if st.button("▶️ Run Copy-Move Detection"):
                try:
                    with st.spinner("Analyzing features... This may take a moment."):
                        cm_image, cm_description, cm_count = detect_copy_move(image)

                    st.markdown(cm_description)

                    if cm_image:
                        st.image(cm_image, caption="Feature Match Visualization", use_container_width=True)
                        st.caption(
                            "Green/red circles: matched feature pairs. "
                            "Yellow lines: connections. Many natural patterns can trigger matches."
                        )
                except Exception as e:
                    st.error(f"❌ Copy-move detection error: {str(e)}")

    # ─── Tab: Report ─────────────────────────────────────────────────────────
    with tab_report:
        st.markdown('<div class="section-header">Forensic Report Generation</div>', unsafe_allow_html=True)

        # Build findings summary
        findings = aggregate_findings(
            metadata_findings=metadata_findings,
            hash_match=hash_match,
            ela_stats=ela_stats,
            copy_move_count=0,  # Updated if copy-move was run
            is_jpeg=jpeg_ok,
        )

        # Display findings summary
        st.markdown("#### Summary of Findings")
        for finding in findings:
            col_cat, col_status = st.columns([3, 1])
            with col_cat:
                st.markdown(f"**{finding['category']}**")
                st.caption(finding["detail"])
            with col_status:
                render_status_badge(finding["status"])
            st.markdown("---")

        # Generate PDF button
        st.markdown("#### Download Report")

        ela_settings_dict = None
        if ela_performed:
            ela_settings_dict = {"quality": ela_quality, "scale": ela_scale}

        if st.button("📄 Generate PDF Forensic Report", type="primary"):
            try:
                with st.spinner("Generating PDF report..."):
                    pdf_bytes = generate_report(
                        filename=filename,
                        basic_properties=basic_props,
                        exif_data=exif_data,
                        camera_info=camera_info,
                        gps_data=gps_data,
                        sha256_hash=sha256_hash,
                        comparison_hash=comparison_hash,
                        hash_match=hash_match,
                        ela_settings=ela_settings_dict,
                        ela_stats=ela_stats,
                        findings=findings,
                        original_image=image,
                        ela_image=ela_image,
                        dimension_analysis=dim_analysis,
                        color_channel_stats=color_stats,
                    )

                # Create a safe filename for download
                safe_name = "".join(c for c in filename if c.isalnum() or c in "._- ")[:40]
                report_name = f"ImageShield_Report_{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

                st.download_button(
                    label="⬇️ Download PDF Report",
                    data=pdf_bytes,
                    file_name=report_name,
                    mime="application/pdf",
                )

                st.success("✅ Report generated successfully! Click the download button above.")

            except Exception as e:
                st.error(f"❌ Report generation failed: {str(e)}")
                st.exception(e)

        # Disclaimer
        st.markdown("---")
        st.markdown(
            '<div class="info-box">'
            "<strong>⚠️ Forensic Disclaimer:</strong> This report is generated by "
            "an automated analysis tool and provides preliminary screening indicators "
            "only. Automated image forensics cannot conclusively prove or disprove "
            "image manipulation. All findings should be interpreted by qualified "
            "forensic professionals in the context of the specific investigation. "
            "This tool is intended for educational and preliminary screening purposes."
            "</div>",
            unsafe_allow_html=True,
        )

    # ─── Footer ──────────────────────────────────────────────────────────────
    st.markdown("""
    <div class="footer">
        ImageShield v1.0 — Digital Image Forensics and Integrity Analysis<br>
        For educational and preliminary forensic screening purposes only.
    </div>
    """, unsafe_allow_html=True)


# ─── Entry Point ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    main()
