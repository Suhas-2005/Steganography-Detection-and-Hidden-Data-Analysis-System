"""
StegAnalyzer — SHA-256 evidence hashing.

SHA-256 (Secure Hash Algorithm 256-bit) produces a unique fixed-length
digest for any input.  In digital forensics it is used to:

  • Uniquely identify a specific file (evidence fingerprinting).
  • Verify that evidence has not been modified during analysis.
  • Provide an integrity record for chain-of-custody documentation.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

# Chunk size for streaming large files without loading them entirely into RAM.
_CHUNK_SIZE: int = 8192

SHA256_EXPLANATION: str = (
    "SHA-256 produces a 256-bit (64-character hex) fingerprint that uniquely "
    "identifies the exact contents of a file.  Even a single-byte change "
    "produces a completely different hash.  This property makes it the "
    "standard method for evidence integrity verification in digital forensics."
)


def calculate_sha256(file_path: Path) -> str:
    """Return the SHA-256 hex digest of the file at *file_path*.

    Reads the file in fixed-size chunks so that large files do not
    consume excessive memory.
    """
    sha = hashlib.sha256()
    with open(file_path, "rb") as fh:
        while chunk := fh.read(_CHUNK_SIZE):
            sha.update(chunk)
    return sha.hexdigest()


def calculate_sha256_from_bytes(data: bytes) -> str:
    """Return the SHA-256 hex digest of raw *data*."""
    return hashlib.sha256(data).hexdigest()


def verify_integrity(file_path: Path, expected_hash: str) -> bool:
    """Return ``True`` when the current hash of *file_path* matches *expected_hash*."""
    return calculate_sha256(file_path).lower() == expected_hash.lower()

