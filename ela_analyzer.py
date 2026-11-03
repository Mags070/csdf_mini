"""
ImageShield — Error Level Analysis (ELA) Module

Implements ELA for JPEG images to help identify regions that may
have been modified. ELA works by re-compressing the image and
comparing the result to the original, highlighting areas with
different compression histories.

IMPORTANT: ELA is a preliminary screening technique, not a definitive
forgery detector. Many factors affect ELA results, including original
compression quality, image content, edges, gradients, and editing
history. Results must be interpreted carefully.
"""

from PIL import Image
import numpy as np
import io
from typing import Tuple, Optional


def perform_ela(
    image: Image.Image,
    quality: int = 90,
    scale: int = 15,
) -> Tuple[Image.Image, np.ndarray]:
    """
    Perform Error Level Analysis on a JPEG image.

    ELA Procedure:
    1. Take the original image (assumed JPEG or converted to JPEG).
    2. Re-save a copy at the specified JPEG quality level.
    3. Compute the absolute pixel-wise difference between the original
       and the recompressed version.
    4. Scale (amplify) the difference to make variations visible.

    In a JPEG that has been saved only once at a given quality, all
    regions should show similar error levels. If a region has been
    pasted from a different source or edited and re-saved, it may
    show a noticeably different error level.

    Args:
        image: PIL Image to analyze (should be from a JPEG source).
        quality: JPEG quality level for recompression (1-100).
                 Lower values amplify differences. Default is 90.
        scale: Multiplier for the difference image to enhance
               visibility. Default is 15.

    Returns:
        Tuple of (ela_image as PIL Image, raw_difference as numpy array).
    """
    # Ensure the image is in RGB mode for consistent processing
    if image.mode != "RGB":
        image = image.convert("RGB")

    # Step 1: Re-compress the image at the specified quality
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=quality)
    buffer.seek(0)
    recompressed = Image.open(buffer)
    recompressed.load()  # Force load so we can close the buffer

    # Step 2: Compute absolute pixel-wise difference
    original_array = np.array(image, dtype=np.float64)
    recompressed_array = np.array(recompressed, dtype=np.float64)
    difference = np.abs(original_array - recompressed_array)

    # Step 3: Scale the difference for visualization
    # Multiply and clip to 0-255 range
    scaled = np.clip(difference * scale, 0, 255).astype(np.uint8)

    ela_image = Image.fromarray(scaled)

    return ela_image, difference


def compute_ela_statistics(difference: np.ndarray) -> dict:
    """
    Compute statistical measures of the ELA difference image.

    These statistics help characterize the overall error level
    distribution. Unusual patterns (very high max, uneven distribution)
    MAY warrant further investigation, but are not conclusive evidence.

    Args:
        difference: Raw difference array from perform_ela().

    Returns:
        Dictionary of statistical measures.
    """
    return {
        "Mean Error Level": f"{np.mean(difference):.4f}",
        "Max Error Level": f"{np.max(difference):.4f}",
        "Min Error Level": f"{np.min(difference):.4f}",
        "Std Deviation": f"{np.std(difference):.4f}",
        "Median Error Level": f"{np.median(difference):.4f}",
    }


def is_jpeg_compatible(image: Image.Image, file_bytes: bytes) -> Tuple[bool, str]:
    """
    Check whether the image is suitable for direct JPEG-based ELA.

    ELA is designed for JPEG images because it relies on JPEG
    compression artifacts. PNG and other lossless formats do not
    exhibit the same compression patterns.

    Args:
        image: PIL Image object.
        file_bytes: Raw file bytes.

    Returns:
        Tuple of (is_compatible, explanation).
    """
    # Check file signature for JPEG (starts with FF D8 FF)
    is_jpeg = (
        len(file_bytes) >= 3
        and file_bytes[0:2] == b'\xff\xd8'
    )

    if is_jpeg or (image.format and image.format.upper() in ("JPEG", "JPG")):
        return (
            True,
            "This image is a JPEG file. ELA can be applied directly."
        )
    elif image.format and image.format.upper() == "PNG":
        return (
            False,
            "This image is a PNG file. Standard JPEG-based ELA is not "
            "directly applicable to PNG's lossless encoding. You can "
            "optionally analyze a JPEG-converted copy, but note that "
            "the results reflect the conversion process rather than "
            "the original PNG compression."
        )
    else:
        return (
            False,
            f"This image format ({image.format}) is not a standard JPEG. "
            "ELA results may not be meaningful."
        )


def convert_and_analyze(
    image: Image.Image,
    quality: int = 90,
    scale: int = 15,
) -> Tuple[Image.Image, np.ndarray]:
    """
    Convert a non-JPEG image to JPEG format in memory, then perform ELA.

    This is offered as an option for PNG images. The results should be
    interpreted with caution as they reflect the initial JPEG conversion
    rather than the original PNG file's compression history.

    Args:
        image: PIL Image to convert and analyze.
        quality: JPEG quality for the initial conversion and re-analysis.
        scale: Visualization scale factor.

    Returns:
        Tuple of (ela_image, raw_difference).
    """
    # Convert image to JPEG in memory first
    if image.mode != "RGB":
        image = image.convert("RGB")

    jpeg_buffer = io.BytesIO()
    image.save(jpeg_buffer, format="JPEG", quality=95)  # High quality initial save
    jpeg_buffer.seek(0)
    jpeg_image = Image.open(jpeg_buffer)
    jpeg_image.load()

    # Now perform standard ELA on the JPEG version
    return perform_ela(jpeg_image, quality=quality, scale=scale)


def get_ela_explanation() -> str:
    """
    Return an educational explanation of ELA for display in the UI.

    Returns:
        Formatted markdown string explaining ELA methodology.
    """
    return (
        "**Error Level Analysis (ELA)** examines JPEG compression artifacts "
        "to identify regions with potentially different compression histories.\n\n"
        "**How it works:**\n"
        "1. The image is re-saved at a known JPEG quality level.\n"
        "2. The pixel-by-pixel difference between the original and "
        "recompressed version is calculated.\n"
        "3. This difference is amplified and displayed as a heat map.\n\n"
        "**Interpretation:**\n"
        "- In an unmodified JPEG, all regions should show similar error levels.\n"
        "- Regions that have been added, pasted, or edited from a different "
        "source *may* show distinctly different error levels.\n"
        "- **Brighter regions** indicate higher error (more difference from "
        "recompression).\n"
        "- **Darker regions** indicate lower error (closer to equilibrium).\n\n"
        "**⚠️ Limitations:**\n"
        "- High-contrast edges naturally produce higher error levels.\n"
        "- Images saved multiple times show reduced overall error.\n"
        "- Different JPEG quality settings affect the baseline.\n"
        "- Resizing, cropping, and color adjustments alter ELA results.\n"
        "- ELA alone **cannot definitively prove** an image is manipulated.\n"
        "- Results should be considered alongside other analysis methods."
    )
