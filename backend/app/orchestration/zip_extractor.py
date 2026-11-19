"""
ZipExtractor — secure ZIP archive extraction with hardened validation.

Security measures:
- Zip-slip prevention via realpath validation
- Bomb detection (compression ratio > 100:1)
- Size enforcement (pre-flight + during extraction)
- File count enforcement
- Nested archive detection and rejection
- Streaming extraction (64KB chunks)
- All operations in asyncio.to_thread
"""

import asyncio
import logging
import os
import shutil
import tempfile
import zipfile
from typing import Optional

logger = logging.getLogger("orchestration.zip_extractor")

# Nested archive extensions to reject
ARCHIVE_EXTENSIONS = {
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".rar", ".7z", ".xz", ".lz",
}

EXTRACT_CHUNK_SIZE = 65536  # 64KB

# Dependency / build directories to skip during extraction
_SKIP_DIRS = frozenset({
    "node_modules", "vendor", "dist", "build", "target", ".git",
    "coverage", "__pycache__", ".next", ".svn", "venv", ".venv",
    "env", ".mypy_cache", ".pytest_cache", ".nyc_output", ".cache",
    "bin", "obj", ".gradle", ".cargo", "bower_components",
    ".terraform", ".tox", ".eggs", ".bundle", "packages", "out",
})

# Binary extensions to skip during extraction
_BINARY_EXTENSIONS = frozenset({
    ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".lib",
    ".pyc", ".pyo", ".class", ".jar", ".war", ".ear",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac", ".webm",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".wasm", ".min.js", ".min.css", ".map",
})


class ZipExtractionError(Exception):
    """Raised on extraction failure."""
    pass


class ZipSlipError(ZipExtractionError):
    """Raised when a zip entry attempts path traversal."""
    pass


class ZipBombError(ZipExtractionError):
    """Raised when a zip bomb is detected."""
    pass


class ZipExtractor:
    """Secure ZIP extractor with comprehensive validation."""

    def __init__(
        self,
        max_extracted_size_mb: int = 500,
        max_file_count: int = 10000,
        max_compression_ratio: int = 100,
        temp_dir: Optional[str] = None,
    ):
        self._max_extracted_bytes = max_extracted_size_mb * 1024 * 1024
        self._max_file_count = max_file_count
        self._max_ratio = max_compression_ratio
        self._temp_dir = temp_dir

    def _validate_zip_preflight(self, zf: zipfile.ZipFile) -> None:
        """Pre-flight validation before extraction."""
        entries = zf.infolist()

        # File count check
        file_count = sum(1 for e in entries if not e.is_dir())
        if file_count > self._max_file_count:
            raise ZipExtractionError(
                f"ZIP contains {file_count} files, "
                f"exceeds limit of {self._max_file_count}"
            )

        # Total decompressed size check
        total_decompressed = sum(
            e.file_size for e in entries if not e.is_dir()
        )
        if total_decompressed > self._max_extracted_bytes:
            size_mb = total_decompressed / (1024 * 1024)
            limit_mb = self._max_extracted_bytes / (1024 * 1024)
            raise ZipExtractionError(
                f"Decompressed size {size_mb:.0f}MB "
                f"exceeds limit of {limit_mb:.0f}MB"
            )

        # Compression ratio check (bomb detection)
        total_compressed = sum(
            e.compress_size for e in entries if not e.is_dir()
        )
        if total_compressed > 0:
            ratio = total_decompressed / total_compressed
            if ratio > self._max_ratio:
                raise ZipBombError(
                    f"Compression ratio {ratio:.0f}:1 exceeds limit of "
                    f"{self._max_ratio}:1 (possible zip bomb)"
                )

        # Nested archive detection
        for entry in entries:
            if entry.is_dir():
                continue
            ext = os.path.splitext(entry.filename)[1].lower()
            if ext in ARCHIVE_EXTENSIONS:
                raise ZipExtractionError(
                    f"Nested archive detected: {entry.filename} — "
                    "nested archives are not supported for security reasons"
                )

    def _validate_path(self, extract_dir: str, entry_path: str) -> str:
        """Validate extraction path to prevent zip-slip attacks."""
        target = os.path.join(extract_dir, entry_path)
        real_target = os.path.realpath(target)
        real_extract = os.path.realpath(extract_dir)

        if (
            not real_target.startswith(real_extract + os.sep)
            and real_target != real_extract
        ):
            raise ZipSlipError(
                f"Zip-slip attempt detected: {entry_path} "
                "resolves outside extract directory"
            )
        return target

    # Per-file size limit (Part 3) — skip individual files larger than this
    MAX_SINGLE_FILE_BYTES = 1_048_576  # 1 MB

    def _extract_streaming(
        self, zf: zipfile.ZipFile, extract_dir: str
    ) -> int:
        """Extract files using streaming (64KB chunks) to control memory.

        Returns total bytes extracted.
        Skips individual files exceeding MAX_SINGLE_FILE_BYTES (Part 3).
        Logs extraction statistics (Part 7).
        """
        total_extracted = 0
        files_extracted = 0
        files_skipped_size = 0
        files_skipped_path = 0
        files_skipped_dir = 0
        files_skipped_binary_ext = 0

        for entry in zf.infolist():
            if entry.is_dir():
                dir_path = self._validate_path(extract_dir, entry.filename)
                os.makedirs(dir_path, exist_ok=True)
                continue

            # Part 1: reject absolute paths and traversal in entry name
            raw_name = entry.filename
            if raw_name.startswith('/') or raw_name.startswith('\\'):
                logger.warning("[SKIP] %s (absolute path)", raw_name)
                files_skipped_path += 1
                continue
            if '..' in raw_name.split('/'):
                logger.warning("[SKIP] %s (path traversal)", raw_name)
                files_skipped_path += 1
                continue

            # Skip files inside dependency/build directories
            parts = raw_name.replace('\\', '/').split('/')
            if any(p in _SKIP_DIRS for p in parts[:-1]):
                logger.debug("[SKIP] %s (dependency/build directory)", raw_name)
                files_skipped_dir += 1
                continue

            # Skip binary file extensions
            ext = os.path.splitext(raw_name)[1].lower()
            if ext in _BINARY_EXTENSIONS:
                logger.debug("[SKIP] %s (binary extension)", raw_name)
                files_skipped_binary_ext += 1
                continue

            # Part 3: skip files larger than per-file limit
            if entry.file_size > self.MAX_SINGLE_FILE_BYTES:
                size_mb = entry.file_size / (1024 * 1024)
                logger.info(
                    "[SKIP] %s (%.1fMB > %dMB limit)",
                    raw_name, size_mb,
                    self.MAX_SINGLE_FILE_BYTES // (1024 * 1024),
                )
                files_skipped_size += 1
                continue

            try:
                target_path = self._validate_path(extract_dir, entry.filename)
            except ZipSlipError:
                logger.warning("[SKIP] %s (zip-slip blocked)", raw_name)
                files_skipped_path += 1
                continue

            # Ensure parent directory exists
            parent = os.path.dirname(target_path)
            os.makedirs(parent, exist_ok=True)

            # Stream extraction (Part 6: context managers)
            with zf.open(entry) as src, open(target_path, "wb") as dst:
                while True:
                    chunk = src.read(EXTRACT_CHUNK_SIZE)
                    if not chunk:
                        break
                    total_extracted += len(chunk)

                    # Runtime size enforcement
                    if total_extracted > self._max_extracted_bytes:
                        raise ZipExtractionError(
                            "Extraction exceeded size limit during streaming"
                        )

                    dst.write(chunk)

            files_extracted += 1

        # Part 7: summary logging
        logger.info(
            "zip_extraction_summary: extracted=%d skipped_size=%d "
            "skipped_path=%d skipped_dir=%d skipped_binary_ext=%d "
            "total_bytes=%d",
            files_extracted, files_skipped_size,
            files_skipped_path, files_skipped_dir, files_skipped_binary_ext,
            total_extracted,
        )
        return total_extracted

    async def extract(self, zip_path: str) -> str:
        """Extract a ZIP file securely.

        Returns the path to the extracted directory.
        Raises ZipExtractionError on failure.
        """
        if not os.path.isfile(zip_path):
            raise ZipExtractionError(f"ZIP file not found: {zip_path}")

        base_dir = self._temp_dir or tempfile.gettempdir()
        extract_dir = tempfile.mkdtemp(prefix="scan-extract-", dir=base_dir)

        def _do_extract() -> int:
            try:
                with zipfile.ZipFile(zip_path, "r") as zf:
                    # Pre-flight validation
                    self._validate_zip_preflight(zf)
                    # Streaming extraction
                    return self._extract_streaming(zf, extract_dir)
            except zipfile.BadZipFile as exc:
                raise ZipExtractionError(
                    f"Invalid ZIP file: {exc}"
                ) from exc

        try:
            total_bytes = await asyncio.to_thread(_do_extract)
            logger.info(
                "ZIP extracted: %d bytes to %s", total_bytes, extract_dir,
            )
            return extract_dir
        except ZipExtractionError:
            shutil.rmtree(extract_dir, ignore_errors=True)
            raise
        except Exception as exc:
            shutil.rmtree(extract_dir, ignore_errors=True)
            raise ZipExtractionError(
                f"Extraction failed: {exc}"
            ) from exc
