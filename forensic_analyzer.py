"""
ImageShield — Forensic Analysis Utilities Module

Provides shared image analysis functions including grayscale conversion,
edge detection, basic copy-move detection (experimental), and
a findings-summary aggregator for the forensic dashboard.
"""

from PIL import Image
import cv2
import numpy as np
from typing import Dict, Any, List, Tuple, Optional
import io


# ─── Status Labels ──────────────────────────────────────────────────────────────

STATUS_INFO = "ℹ️ Information Available"
STATUS_ANOMALY = "⚠️ Potential Anomaly"
STATUS_INCONCLUSIVE = "❓ Inconclusive"
STATUS_UNAVAILABLE = "🚫 Analysis Unavailable"


def pil_to_cv2(image: Image.Image) -> np.ndarray:
    """
    Convert a PIL Image to an OpenCV-compatible BGR numpy array.

    Args:
        image: PIL Image object.

    Returns:
        OpenCV BGR image as numpy array.
    """
    if image.mode == "RGBA":
        image = image.convert("RGB")
    elif image.mode != "RGB":
        image = image.convert("RGB")

    rgb_array = np.array(image)
    # Convert RGB (PIL) to BGR (OpenCV)
    bgr_array = cv2.cvtColor(rgb_array, cv2.COLOR_RGB2BGR)
    return bgr_array


def cv2_to_pil(cv2_image: np.ndarray) -> Image.Image:
    """
    Convert an OpenCV BGR image to a PIL Image (RGB).

    Args:
        cv2_image: OpenCV BGR image array.

    Returns:
        PIL Image in RGB mode.
    """
    if len(cv2_image.shape) == 2:
        # Grayscale image
        return Image.fromarray(cv2_image, mode="L")
    else:
        rgb_array = cv2.cvtColor(cv2_image, cv2.COLOR_BGR2RGB)
        return Image.fromarray(rgb_array)


def generate_grayscale(image: Image.Image) -> Image.Image:
    """
    Convert image to grayscale for analysis visualization.

    Args:
        image: PIL Image object.

    Returns:
        Grayscale PIL Image.
    """
    cv2_img = pil_to_cv2(image)
    gray = cv2.cvtColor(cv2_img, cv2.COLOR_BGR2GRAY)
    return cv2_to_pil(gray)


def detect_edges(image: Image.Image, low_threshold: int = 50, high_threshold: int = 150) -> Image.Image:
    """
    Perform Canny edge detection on the image.

    Edge detection highlights boundaries and transitions in the image.
    Inconsistent edge patterns *may* indicate editing, but edges are
    also affected by image content, compression, and resolution.

    Args:
        image: PIL Image object.
        low_threshold: Lower threshold for Canny edge detection.
        high_threshold: Upper threshold for Canny edge detection.

    Returns:
        Edge-detected image as PIL Image.
    """
    cv2_img = pil_to_cv2(image)
    gray = cv2.cvtColor(cv2_img, cv2.COLOR_BGR2GRAY)

    # Apply Gaussian blur to reduce noise before edge detection
    blurred = cv2.GaussianBlur(gray, (5, 5), 0)

    # Canny edge detection
    edges = cv2.Canny(blurred, low_threshold, high_threshold)

    return cv2_to_pil(edges)


def analyze_color_channels(image: Image.Image) -> Dict[str, Any]:
    """
    Analyze individual color channels for statistical properties.

    Significant differences between channel statistics may indicate
    processing or compositing, but can also occur naturally.

    Args:
        image: PIL Image object.

    Returns:
        Dictionary with per-channel statistics.
    """
    cv2_img = pil_to_cv2(image)

    if len(cv2_img.shape) < 3:
        return {"Note": "Image is grayscale — single channel only."}

    channels = {
        "Blue": cv2_img[:, :, 0],
        "Green": cv2_img[:, :, 1],
        "Red": cv2_img[:, :, 2],
    }

    stats = {}
    for name, channel in channels.items():
        stats[name] = {
            "Mean": f"{np.mean(channel):.2f}",
            "Std Dev": f"{np.std(channel):.2f}",
            "Min": int(np.min(channel)),
            "Max": int(np.max(channel)),
        }

    return stats


def detect_copy_move(image: Image.Image, min_match_count: int = 10) -> Tuple[Optional[Image.Image], str, int]:
    """
    Experimental copy-move detection using ORB feature matching.

    This function attempts to detect duplicated regions within an image
    by finding similar feature descriptors in different locations.

    ⚠️ EXPERIMENTAL: This is a simplified implementation and has
    significant limitations:
    - High false-positive rate on images with repetitive patterns
      (tiles, fabric, sky, grass, architecture).
    - May miss sophisticated copy-move forgeries that use blending,
      scaling, or rotation.
    - Intended for educational/demonstration purposes only.

    Args:
        image: PIL Image to analyze.
        min_match_count: Minimum number of feature matches to report.

    Returns:
        Tuple of (visualization image or None, description, match_count).
    """
    cv2_img = pil_to_cv2(image)
    gray = cv2.cvtColor(cv2_img, cv2.COLOR_BGR2GRAY)

    # Use ORB (Oriented FAST and Rotated BRIEF) feature detector
    orb = cv2.ORB_create(nfeatures=1000)
    keypoints, descriptors = orb.detectAndCompute(gray, None)

    if descriptors is None or len(keypoints) < min_match_count:
        return (
            None,
            "Insufficient features detected for copy-move analysis. "
            "This may occur with very simple or very small images.",
            0,
        )

    # Use brute-force matcher to find similar features within the same image
    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=False)
    matches = bf.knnMatch(descriptors, descriptors, k=2)

    # Filter: keep matches where the two matched keypoints are
    # sufficiently far apart (indicating duplication, not self-match)
    suspicious_matches = []
    min_distance_px = 40  # Minimum pixel distance to avoid self-matching

    for match_pair in matches:
        if len(match_pair) < 2:
            continue
        m, n = match_pair

        # Skip self-matches (same keypoint index)
        if m.queryIdx == m.trainIdx:
            continue

        # Ratio test (Lowe's ratio)
        if m.distance < 0.75 * n.distance:
            pt1 = keypoints[m.queryIdx].pt
            pt2 = keypoints[m.trainIdx].pt
            dist = np.sqrt((pt1[0] - pt2[0]) ** 2 + (pt1[1] - pt2[1]) ** 2)

            if dist > min_distance_px:
                suspicious_matches.append(m)

    match_count = len(suspicious_matches)

    if match_count < min_match_count:
        return (
            None,
            f"Found {match_count} potential feature matches (below threshold "
            f"of {min_match_count}). No significant copy-move patterns detected. "
            "This does not guarantee the image is unmanipulated.",
            match_count,
        )

    # Draw matches on the image for visualization
    result_img = cv2_img.copy()
    for match in suspicious_matches[:50]:  # Limit drawn matches
        pt1 = tuple(map(int, keypoints[match.queryIdx].pt))
        pt2 = tuple(map(int, keypoints[match.trainIdx].pt))
        cv2.circle(result_img, pt1, 4, (0, 255, 0), 2)
        cv2.circle(result_img, pt2, 4, (0, 0, 255), 2)
        cv2.line(result_img, pt1, pt2, (255, 255, 0), 1)

    description = (
        f"Found {match_count} potential copy-move feature matches. "
        "Green and red circles indicate matched feature pairs; yellow lines "
        "connect them. **⚠️ Important:** Repetitive textures, patterns, and "
        "symmetrical objects naturally produce similar features. High match "
        "counts do NOT automatically indicate forgery. Manual review is required."
    )

    return (cv2_to_pil(result_img), description, match_count)


def get_image_dimensions_analysis(image: Image.Image) -> Dict[str, Any]:
    """
    Analyze image dimensions and identify any notable properties.

    Args:
        image: PIL Image object.

    Returns:
        Dictionary with dimension analysis results.
    """
    width, height = image.size
    aspect_ratio = width / height if height > 0 else 0

    # Common aspect ratios
    common_ratios = {
        "4:3": 4 / 3,
        "3:2": 3 / 2,
        "16:9": 16 / 9,
        "1:1": 1.0,
        "16:10": 16 / 10,
        "3:4": 3 / 4,
        "2:3": 2 / 3,
        "9:16": 9 / 16,
    }

    closest_ratio = min(common_ratios.items(), key=lambda x: abs(x[1] - aspect_ratio))

    return {
        "Width": width,
        "Height": height,
        "Aspect Ratio": f"{aspect_ratio:.4f}",
        "Closest Standard Ratio": closest_ratio[0],
        "Total Pixels": f"{width * height:,}",
        "Color Mode": image.mode,
        "Color Channels": len(image.getbands()),
        "Channel Names": ", ".join(image.getbands()),
    }


def aggregate_findings(
    metadata_findings: Dict[str, str],
    hash_match: Optional[bool],
    ela_stats: Optional[Dict[str, str]],
    copy_move_count: int,
    is_jpeg: bool,
) -> List[Dict[str, str]]:
    """
    Aggregate all analysis findings into a structured summary.

    Each finding includes a category, status label, and description.
    Status labels follow the convention:
    - Information Available: Data was found and displayed.
    - Potential Anomaly: Something that may warrant investigation.
    - Inconclusive: Analysis ran but no strong signal either way.
    - Analysis Unavailable: The analysis could not be performed.

    Args:
        metadata_findings: Results from metadata forensic summary.
        hash_match: True if hashes matched, False if not, None if not compared.
        ela_stats: ELA statistics dictionary, or None.
        copy_move_count: Number of copy-move feature matches found.
        is_jpeg: Whether the image is a JPEG file.

    Returns:
        List of finding dictionaries with 'category', 'status', and 'detail'.
    """
    findings = []

    # Metadata findings
    for key, value in metadata_findings.items():
        status = STATUS_INFO
        if "editing software" in key.lower() or "difference" in key.lower():
            status = STATUS_ANOMALY
        findings.append({
            "category": f"Metadata: {key}",
            "status": status,
            "detail": value,
        })

    # Hash comparison
    if hash_match is True:
        findings.append({
            "category": "Integrity: Hash Comparison",
            "status": STATUS_INFO,
            "detail": "Files are byte-for-byte identical.",
        })
    elif hash_match is False:
        findings.append({
            "category": "Integrity: Hash Comparison",
            "status": STATUS_INFO,
            "detail": "Files have different hash values — they are not identical.",
        })

    # ELA results
    if ela_stats:
        mean_error = float(ela_stats.get("Mean Error Level", "0"))
        if mean_error > 20:
            status = STATUS_ANOMALY
            detail = (
                f"Elevated mean error level ({ela_stats['Mean Error Level']}). "
                "This may indicate editing, but can also result from high JPEG "
                "quality or certain image content."
            )
        else:
            status = STATUS_INFO
            detail = (
                f"Mean error level is {ela_stats['Mean Error Level']}. "
                "Error distribution appears within expected range for a JPEG image."
            )
        findings.append({
            "category": "ELA: Error Level Analysis",
            "status": status,
            "detail": detail,
        })
    elif not is_jpeg:
        findings.append({
            "category": "ELA: Error Level Analysis",
            "status": STATUS_UNAVAILABLE,
            "detail": "Standard ELA is designed for JPEG files. Not applied to this image format.",
        })

    # Copy-move detection
    if copy_move_count >= 10:
        findings.append({
            "category": "Copy-Move Detection (Experimental)",
            "status": STATUS_INCONCLUSIVE,
            "detail": (
                f"Found {copy_move_count} potential feature matches. "
                "This is experimental and may include false positives from "
                "repetitive patterns."
            ),
        })

    return findings
