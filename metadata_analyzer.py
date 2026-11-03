"""
ImageShield — Metadata and EXIF Analysis Module

Extracts and interprets image metadata including EXIF fields,
GPS coordinates, camera info, and software details from digital images.
"""

from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from typing import Dict, Any, Optional, List, Tuple
import io


# ─── Human-readable EXIF tag names ─────────────────────────────────────────────

# Tags that are commonly relevant in digital forensics
FORENSIC_PRIORITY_TAGS = [
    "Make", "Model", "Software", "DateTime", "DateTimeOriginal",
    "DateTimeDigitized", "ExposureTime", "FNumber", "ISOSpeedRatings",
    "FocalLength", "ImageWidth", "ImageLength", "Orientation",
    "XResolution", "YResolution", "ResolutionUnit", "ColorSpace",
    "ExifImageWidth", "ExifImageHeight", "WhiteBalance", "Flash",
    "MeteringMode", "LightSource", "SceneCaptureType",
    "ExifVersion", "ComponentsConfiguration",
]

# GPS sub-tag mapping for readable field names
GPS_TAG_NAMES = {v: k for k, v in GPSTAGS.items()}


def get_basic_properties(image: Image.Image, file_bytes: bytes) -> Dict[str, Any]:
    """
    Extract basic image properties that are always available.

    Args:
        image: A PIL Image object.
        file_bytes: The raw bytes of the uploaded file.

    Returns:
        Dictionary with format, dimensions, color mode, and file size.
    """
    width, height = image.size
    file_size_bytes = len(file_bytes)

    # Format human-readable file size
    if file_size_bytes < 1024:
        size_str = f"{file_size_bytes} bytes"
    elif file_size_bytes < 1024 * 1024:
        size_str = f"{file_size_bytes / 1024:.2f} KB"
    else:
        size_str = f"{file_size_bytes / (1024 * 1024):.2f} MB"

    return {
        "Filename Format": image.format if image.format else "Unknown",
        "Width (px)": width,
        "Height (px)": height,
        "Color Mode": image.mode,
        "File Size": size_str,
        "File Size (bytes)": file_size_bytes,
        "Megapixels": f"{(width * height) / 1_000_000:.2f} MP",
    }


def extract_exif_data(image: Image.Image) -> Optional[Dict[str, Any]]:
    """
    Extract all available EXIF metadata from the image.

    EXIF data may be absent (e.g., screenshots, web images) or may have
    been stripped or altered. Its presence or absence alone does not
    prove authenticity or manipulation.

    Args:
        image: A PIL Image object.

    Returns:
        Dictionary of decoded EXIF tag-name to value pairs, or None if
        no EXIF data is present.
    """
    try:
        exif_data = image._getexif()
    except (AttributeError, Exception):
        # Image format does not support EXIF (e.g., some PNGs)
        return None

    if exif_data is None:
        return None

    decoded = {}
    for tag_id, value in exif_data.items():
        tag_name = TAGS.get(tag_id, f"Unknown Tag ({tag_id})")

        # Skip binary blobs that aren't human-readable
        if isinstance(value, bytes) and len(value) > 100:
            decoded[tag_name] = f"[Binary data, {len(value)} bytes]"
        elif isinstance(value, bytes):
            try:
                decoded[tag_name] = value.decode("utf-8", errors="replace")
            except Exception:
                decoded[tag_name] = f"[Binary data, {len(value)} bytes]"
        else:
            decoded[tag_name] = value

    return decoded if decoded else None


def extract_gps_data(image: Image.Image) -> Optional[Dict[str, Any]]:
    """
    Extract GPS metadata if available in the EXIF data.

    GPS coordinates in metadata indicate where the photo was taken
    according to the device, but can be spoofed or modified.

    Args:
        image: A PIL Image object.

    Returns:
        Dictionary with GPS fields, or None if GPS data is absent.
    """
    try:
        exif_data = image._getexif()
    except (AttributeError, Exception):
        return None

    if exif_data is None:
        return None

    # GPS info is stored under a specific EXIF tag (tag 34853)
    gps_tag_id = None
    for tag_id, tag_name in TAGS.items():
        if tag_name == "GPSInfo":
            gps_tag_id = tag_id
            break

    if gps_tag_id is None or gps_tag_id not in exif_data:
        return None

    gps_info = exif_data[gps_tag_id]
    if not isinstance(gps_info, dict):
        return None

    decoded_gps = {}
    for key, value in gps_info.items():
        gps_tag_name = GPSTAGS.get(key, f"Unknown GPS Tag ({key})")
        decoded_gps[gps_tag_name] = value

    return decoded_gps if decoded_gps else None


def convert_gps_to_decimal(gps_data: Dict[str, Any]) -> Optional[Tuple[float, float]]:
    """
    Convert GPS coordinates from degrees/minutes/seconds to decimal format.

    Args:
        gps_data: Dictionary containing GPS EXIF fields.

    Returns:
        Tuple of (latitude, longitude) in decimal degrees, or None.
    """
    try:
        lat = gps_data.get("GPSLatitude")
        lat_ref = gps_data.get("GPSLatitudeRef")
        lon = gps_data.get("GPSLongitude")
        lon_ref = gps_data.get("GPSLongitudeRef")

        if not all([lat, lat_ref, lon, lon_ref]):
            return None

        def dms_to_decimal(dms_tuple, ref):
            """Convert degrees, minutes, seconds to decimal degrees."""
            degrees = float(dms_tuple[0])
            minutes = float(dms_tuple[1])
            seconds = float(dms_tuple[2])
            decimal = degrees + minutes / 60.0 + seconds / 3600.0
            if ref in ("S", "W"):
                decimal = -decimal
            return decimal

        lat_decimal = dms_to_decimal(lat, lat_ref)
        lon_decimal = dms_to_decimal(lon, lon_ref)

        return (lat_decimal, lon_decimal)

    except (TypeError, ValueError, IndexError, ZeroDivisionError):
        return None


def get_camera_info(exif_data: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """
    Extract camera-specific information from EXIF data.

    Args:
        exif_data: Decoded EXIF dictionary from extract_exif_data().

    Returns:
        Dictionary with camera make, model, software, and timestamp fields.
    """
    if exif_data is None:
        return {}

    camera_fields = {
        "Camera Manufacturer": exif_data.get("Make", "Not available"),
        "Camera Model": exif_data.get("Model", "Not available"),
        "Software": exif_data.get("Software", "Not available"),
        "Date/Time Original": exif_data.get("DateTimeOriginal", "Not available"),
        "Date/Time Digitized": exif_data.get("DateTimeDigitized", "Not available"),
        "Date/Time Modified": exif_data.get("DateTime", "Not available"),
    }

    # Remove entries that are just "Not available"
    return {k: v for k, v in camera_fields.items() if v != "Not available"}


def get_forensic_summary(
    exif_data: Optional[Dict[str, Any]],
    gps_data: Optional[Dict[str, Any]],
) -> Dict[str, str]:
    """
    Generate a forensic summary of the metadata analysis.

    This summary identifies what metadata is available, what is missing,
    and any fields that may warrant further investigation. It does NOT
    make definitive claims about image authenticity.

    Args:
        exif_data: Decoded EXIF dictionary.
        gps_data: Decoded GPS dictionary.

    Returns:
        Dictionary of finding labels to descriptions.
    """
    findings = {}

    if exif_data is None:
        findings["EXIF Data"] = (
            "No EXIF metadata found. This is common for screenshots, "
            "web-downloaded images, and images processed by applications "
            "that strip metadata. Absence of EXIF data alone does not "
            "indicate manipulation."
        )
    else:
        findings["EXIF Data"] = (
            f"EXIF metadata is present with {len(exif_data)} field(s). "
            "Metadata can be modified or fabricated; its presence does not "
            "guarantee the image is unaltered."
        )

        # Check for software editing indicators
        software = exif_data.get("Software", "")
        if software and isinstance(software, str):
            editing_software = [
                "photoshop", "gimp", "lightroom", "snapseed",
                "pixelmator", "affinity", "paint.net", "canva",
            ]
            software_lower = software.lower()
            for editor in editing_software:
                if editor in software_lower:
                    findings["Editing Software"] = (
                        f"Software field contains '{software}'. This suggests "
                        "the image may have been processed with image editing "
                        "software. However, many legitimate workflows involve "
                        "post-processing."
                    )
                    break

        # Check timestamp consistency
        dt_original = exif_data.get("DateTimeOriginal")
        dt_digitized = exif_data.get("DateTimeDigitized")
        dt_modified = exif_data.get("DateTime")

        timestamps_present = sum(
            1 for t in [dt_original, dt_digitized, dt_modified] if t
        )
        if timestamps_present > 1:
            if dt_original and dt_modified and dt_original != dt_modified:
                findings["Timestamp Difference"] = (
                    f"Original timestamp ({dt_original}) differs from "
                    f"modification timestamp ({dt_modified}). This may "
                    "indicate post-processing, or simply that the file was "
                    "saved at a different time."
                )

    if gps_data:
        findings["GPS Data"] = (
            "GPS location data is present. This indicates the capturing "
            "device recorded location information. GPS data can be added, "
            "modified, or spoofed."
        )
    else:
        findings["GPS Data"] = (
            "No GPS location data found. Many devices have location "
            "services disabled, or metadata may have been stripped."
        )

    return findings
