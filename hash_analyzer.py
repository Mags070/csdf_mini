"""
ImageShield — SHA-256 Hash Verification Module

Computes SHA-256 cryptographic hashes of file bytes for integrity
verification and compares hashes between two files to determine
whether they are byte-for-byte identical.
"""

import hashlib
from typing import Tuple


def compute_sha256(file_bytes: bytes) -> str:
    """
    Compute the SHA-256 hash of the given file bytes.

    SHA-256 (Secure Hash Algorithm 256-bit) produces a fixed-size
    256-bit (32-byte) hash value. Even a single-bit change in the
    input produces a completely different hash, making it suitable
    for verifying file integrity.

    The hash is computed from the original file bytes — not from a
    decoded-and-re-encoded image — to ensure the hash reflects the
    exact file content.

    Args:
        file_bytes: Raw bytes of the file to hash.

    Returns:
        Hexadecimal string representation of the SHA-256 hash.
    """
    sha256_hash = hashlib.sha256()

    # Process in chunks for memory efficiency with large files
    chunk_size = 8192
    offset = 0
    while offset < len(file_bytes):
        sha256_hash.update(file_bytes[offset : offset + chunk_size])
        offset += chunk_size

    return sha256_hash.hexdigest()


def compare_hashes(hash1: str, hash2: str) -> Tuple[bool, str]:
    """
    Compare two SHA-256 hashes and provide a forensic interpretation.

    Matching hashes mean the two files are byte-for-byte identical.
    Different hashes mean the files differ in at least one byte, but
    this does NOT necessarily mean the images look different — metadata
    changes, re-encoding, format conversion, and even invisible edits
    can change the hash.

    Args:
        hash1: SHA-256 hex string of the first file.
        hash2: SHA-256 hex string of the second file.

    Returns:
        Tuple of (match_result, explanation_text).
    """
    # Normalize to lowercase for comparison
    hash1 = hash1.strip().lower()
    hash2 = hash2.strip().lower()

    if hash1 == hash2:
        return (
            True,
            "✅ **Hashes Match** — The two files are byte-for-byte identical. "
            "Every single byte in both files is the same, confirming they "
            "are exact copies. No modification of any kind — including "
            "metadata, pixel data, or file structure — has occurred between "
            "these two files."
        )
    else:
        return (
            False,
            "❌ **Hashes Do Not Match** — The two files differ in at least "
            "one byte. This means they are not identical copies. However, "
            "different hashes do NOT necessarily mean the images look "
            "different visually. Common causes of hash differences include:\n"
            "- Re-saving or re-encoding the image\n"
            "- Metadata changes (editing timestamps, stripping EXIF data)\n"
            "- Format conversion (e.g., JPEG → PNG → JPEG)\n"
            "- Image compression at a different quality level\n"
            "- Any editing, cropping, or resizing\n\n"
            "A hash comparison verifies file-level identity, not visual "
            "similarity."
        )


def get_hash_info() -> str:
    """
    Return an educational explanation of SHA-256 hashing for display.

    Returns:
        Formatted string explaining SHA-256 in a forensic context.
    """
    return (
        "**SHA-256 (Secure Hash Algorithm 256-bit)** is a cryptographic "
        "hash function that converts any input data into a fixed-size "
        "64-character hexadecimal string.\n\n"
        "**Key Properties:**\n"
        "- **Deterministic:** The same input always produces the same hash.\n"
        "- **Avalanche Effect:** Even a 1-bit change in the input produces "
        "a completely different hash.\n"
        "- **One-Way:** It is computationally infeasible to reverse-engineer "
        "the original data from its hash.\n"
        "- **Collision-Resistant:** It is extremely unlikely that two "
        "different inputs produce the same hash.\n\n"
        "**Forensic Use:** SHA-256 hashes are used to verify that digital "
        "evidence has not been altered. By recording the hash at the time "
        "of evidence collection, investigators can later confirm the file "
        "has not been modified."
    )
