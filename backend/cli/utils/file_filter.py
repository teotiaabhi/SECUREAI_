"""File filtering utilities for CLI — binary detection and skip logic."""

import os
from typing import Set

from engine.file_classifier import SKIP_DIRECTORIES, SKIP_EXTENSIONS, should_skip_file

# Re-export for convenience
skip_directories: Set[str] = SKIP_DIRECTORIES
skip_extensions: Set[str] = SKIP_EXTENSIONS


def is_binary_file(file_path: str, sample_size: int = 8192) -> bool:
    """Detect binary files by checking for null bytes in the first N bytes."""
    try:
        with open(file_path, "rb") as fh:
            chunk = fh.read(sample_size)
            return b"\x00" in chunk
    except (OSError, IOError):
        return True


def should_skip(file_path: str) -> bool:
    """Check if a file should be skipped (delegates to engine)."""
    return should_skip_file(file_path)
