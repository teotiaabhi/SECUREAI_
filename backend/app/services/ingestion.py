"""
File Ingestion Pipeline
Converts all input sources (paste, upload, multi-file, ZIP, GitHub) into
a unified list of file records: [{filename, path, extension, content}]
"""

import os
import io
import zipfile
from typing import List, Optional
from dataclasses import dataclass, field
from fastapi import UploadFile
from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger("ingestion")

IGNORED_DIRS = {
    "node_modules", "dist", "build", ".next", "__pycache__", ".git",
    ".svn", "vendor", "venv", ".venv", "env", ".mypy_cache", ".pytest_cache",
    "coverage", ".nyc_output", ".cache", "target", "bin", "obj",
    ".gradle", ".cargo", "bower_components", ".terraform", ".tox",
    ".eggs", ".bundle", "packages", "out",
}

IGNORED_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".pyc", ".pyo", ".class",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".lock", ".min.js", ".min.css", ".map",
}

CODE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rs", ".rb",
    ".php", ".cs", ".cpp", ".c", ".h", ".hpp", ".swift", ".kt", ".kts",
    ".sql", ".sh", ".bash", ".zsh", ".ps1", ".yaml", ".yml", ".json",
    ".xml", ".html", ".htm", ".css", ".scss", ".sass", ".less",
    ".tf", ".hcl", ".toml", ".ini", ".cfg", ".conf", ".env",
    ".dockerfile", ".graphql", ".proto", ".vue", ".svelte",
}

# Magic byte signatures for binary file detection
BINARY_MAGIC = [
    (b'\x7fELF', 'ELF'),
    (b'MZ', 'PE'),
    (b'\x89PNG', 'PNG'),
    (b'\xff\xd8\xff', 'JPEG'),
    (b'GIF87a', 'GIF'),
    (b'GIF89a', 'GIF'),
    (b'PK\x03\x04', 'ZIP'),
    (b'\x1f\x8b', 'GZIP'),
    (b'Rar!', 'RAR'),
    (b'\xca\xfe\xba\xbe', 'Mach-O'),
    (b'\x00asm', 'WASM'),
]


def _is_binary_file(content: bytes) -> bool:
    """Detect binary files via magic bytes + null-byte heuristic."""
    for magic, _ in BINARY_MAGIC:
        if content[:len(magic)] == magic:
            return True
    # Null-byte heuristic: >1% null bytes in first 8KB = binary
    sample = content[:8192]
    if sample and sample.count(b'\x00') / len(sample) > 0.01:
        return True
    return False


def _is_polyglot(content: bytes, filename: str) -> bool:
    """Detect files that claim to be source code but contain binary data."""
    ext = os.path.splitext(filename)[1].lower()
    if ext in CODE_EXTENSIONS and _is_binary_file(content):
        return True
    return False


def _validate_path_safe(filename: str) -> str:
    """Sanitize filename: reject path traversal, absolute paths, null bytes."""
    if not filename:
        raise ValueError("Empty filename")
    if '\x00' in filename:
        raise ValueError("Null byte in filename")
    normalized = filename.replace('\\', '/')
    if normalized.startswith('/') or (len(normalized) > 1 and normalized[1] == ':'):
        raise ValueError("Absolute paths not allowed")
    parts = normalized.split('/')
    if '..' in parts:
        raise ValueError("Path traversal not allowed")
    return os.path.basename(normalized)


@dataclass
class IngestedFile:
    filename: str
    path: str
    extension: str
    content: str
    size: int = 0
    errors: list = field(default_factory=list)


def _should_ignore(path: str) -> bool:
    parts = path.replace("\\", "/").split("/")
    for part in parts:
        if part in IGNORED_DIRS:
            return True
    ext = os.path.splitext(path)[1].lower()
    if ext in IGNORED_EXTENSIONS:
        return True
    return False


def _is_code_file(path: str) -> bool:
    basename = os.path.basename(path).lower()
    # Special config files
    if basename in {"dockerfile", "makefile", "jenkinsfile", ".env", ".env.example", "docker-compose.yml", "package.json", "tsconfig.json", "requirements.txt", "go.mod", "cargo.toml", "pom.xml", "build.gradle"}:
        return True
    ext = os.path.splitext(path)[1].lower()
    return ext in CODE_EXTENSIONS


def _validate_file(content: str, filename: str) -> List[str]:
    errors = []
    settings = get_settings()
    max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    if len(content.encode("utf-8", errors="ignore")) > max_bytes:
        errors.append(f"File exceeds {settings.MAX_FILE_SIZE_MB}MB limit")
    return errors


def ingest_paste(code: str, filename: str = "paste.txt", language: str = "auto") -> List[IngestedFile]:
    ext_map = {
        "python": ".py", "javascript": ".js", "typescript": ".ts", "java": ".java",
        "go": ".go", "rust": ".rs", "ruby": ".rb", "php": ".php", "csharp": ".cs",
        "cpp": ".cpp", "c": ".c", "swift": ".swift", "kotlin": ".kt",
        "sql": ".sql", "shell": ".sh", "yaml": ".yaml", "json": ".json",
        "html": ".html", "css": ".css",
    }
    ext = ext_map.get(language.lower(), os.path.splitext(filename)[1] or ".txt")
    errors = _validate_file(code, filename)
    return [IngestedFile(
        filename=filename,
        path=filename,
        extension=ext,
        content=code,
        size=len(code.encode("utf-8", errors="ignore")),
        errors=errors,
    )]


async def ingest_upload(files: List[UploadFile]) -> List[IngestedFile]:
    result = []
    settings = get_settings()
    for f in files[:settings.MAX_FILES_PER_SCAN]:
        try:
            raw = await f.read()
            fname = f.filename or "unknown"

            # Validate filename for path traversal
            try:
                safe_name = _validate_path_safe(fname)
            except ValueError as ve:
                logger.warning("unsafe_filename", filename=fname, reason=str(ve))
                continue

            # Skip binary and polyglot files
            if _is_binary_file(raw):
                logger.warning("binary_file_skipped", filename=safe_name)
                continue
            if _is_polyglot(raw, safe_name):
                logger.warning("polyglot_file_skipped", filename=safe_name)
                continue

            content = raw.decode("utf-8", errors="ignore")
            ext = os.path.splitext(safe_name)[1].lower()
            errors = _validate_file(content, safe_name)
            if not _should_ignore(fname):
                result.append(IngestedFile(
                    filename=safe_name,
                    path=fname,
                    extension=ext,
                    content=content,
                    size=len(raw),
                    errors=errors,
                ))
        except Exception as e:
            logger.error("file_read_error", filename=f.filename, error=str(e))
    return result


async def ingest_zip(upload: UploadFile) -> List[IngestedFile]:
    """Legacy ZIP ingestion path (used for small/direct uploads).

    Hardened with all 8 parts:
    - Part 1: Safe extraction (path traversal + absolute path rejection)
    - Part 2: File count limit (MAX_FILES_PER_SCAN)
    - Part 3: Per-file size limit (MAX_FILE_SIZE_MB)
    - Part 4: Binary file detection and skip
    - Part 5: Directory filtering (IGNORED_DIRS)
    - Part 6: File handle safety (context managers)
    - Part 7: Comprehensive logging
    - Part 8: Failure handling (log + continue)
    """
    result = []
    settings = get_settings()
    max_file_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    files_skipped_path = 0
    files_skipped_size = 0
    files_skipped_binary = 0
    files_skipped_ignored = 0
    files_skipped_ratio = 0
    files_errored = 0
    raw = await upload.read()
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            # Check total uncompressed size (zip bomb protection)
            total_uncompressed = sum(i.file_size for i in zf.infolist())
            max_extracted = getattr(settings, 'ZIP_MAX_EXTRACTED_SIZE_MB', 500) * 1024 * 1024
            if total_uncompressed > max_extracted:
                logger.warning("zip_bomb_detected", total_size=total_uncompressed)
                return result

            for info in zf.infolist():
                if info.is_dir():
                    continue

                # Part 1: Validate filename for path traversal and absolute paths
                try:
                    _validate_path_safe(info.filename)
                except ValueError as ve:
                    logger.warning("zip_unsafe_path", filename=info.filename, reason=str(ve))
                    files_skipped_path += 1
                    continue

                # Reject symlinks (external_attr >> 28 == 0xA for symlinks on Unix)
                unix_attrs = info.external_attr >> 16
                if unix_attrs != 0 and (unix_attrs & 0o170000) == 0o120000:
                    logger.warning("zip_symlink_skipped", filename=info.filename)
                    files_skipped_path += 1
                    continue

                # Part 5: Directory filtering
                if _should_ignore(info.filename):
                    logger.info("[SKIP] %s (ignored dir/extension)", info.filename)
                    files_skipped_ignored += 1
                    continue
                if not _is_code_file(info.filename):
                    logger.debug("[SKIP] %s (unsupported file type)", info.filename)
                    files_skipped_ignored += 1
                    continue

                # Part 2: File count limit
                if len(result) >= settings.MAX_FILES_PER_SCAN:
                    logger.warning(
                        "zip_file_limit_reached",
                        limit=settings.MAX_FILES_PER_SCAN,
                    )
                    break

                # Part 3: Per-file size limit
                if info.file_size > max_file_bytes:
                    size_mb = info.file_size / (1024 * 1024)
                    logger.info(
                        "[SKIP] %s (%.1fMB > %dMB limit)",
                        info.filename, size_mb,
                        max_file_bytes // (1024 * 1024),
                    )
                    files_skipped_size += 1
                    continue

                # Check compression ratio per file (zip bomb detection)
                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    max_ratio = getattr(settings, 'ZIP_MAX_COMPRESSION_RATIO', 100)
                    if ratio > max_ratio:
                        logger.warning("zip_high_ratio", filename=info.filename, ratio=ratio)
                        files_skipped_ratio += 1
                        continue

                try:
                    # Part 6: ZipFile.read uses internal handles safely
                    file_bytes = zf.read(info.filename)

                    # Part 4: Skip binary files inside ZIPs
                    if _is_binary_file(file_bytes):
                        logger.info("[SKIP] %s (binary file)", info.filename)
                        files_skipped_binary += 1
                        continue

                    content = file_bytes.decode("utf-8", errors="ignore")
                    ext = os.path.splitext(info.filename)[1].lower()
                    errors = _validate_file(content, info.filename)
                    result.append(IngestedFile(
                        filename=os.path.basename(info.filename),
                        path=info.filename,
                        extension=ext,
                        content=content,
                        size=info.file_size,
                        errors=errors,
                    ))
                except Exception as e:
                    # Part 8: log error, continue scanning remaining files
                    logger.error("zip_file_error", file=info.filename, error=str(e))
                    files_errored += 1
    except zipfile.BadZipFile:
        logger.error("bad_zip_file")

    # Part 7: Comprehensive logging
    logger.info(
        "zip_ingest_summary",
        extracted=len(result),
        skipped_path=files_skipped_path,
        skipped_size=files_skipped_size,
        skipped_binary=files_skipped_binary,
        skipped_ignored=files_skipped_ignored,
        skipped_ratio=files_skipped_ratio,
        errored=files_errored,
    )
    return result


async def ingest_github(user, repo_full_name: str, branch: str = "main") -> List[IngestedFile]:
    from app.auth.oauth_github import fetch_repo_tree, fetch_file_content

    result = []
    settings = get_settings()

    tree = await fetch_repo_tree(user, repo_full_name, branch)
    code_files = [f for f in tree if _is_code_file(f["path"]) and not _should_ignore(f["path"])]
    code_files = code_files[:settings.MAX_FILES_PER_SCAN]

    for file_info in code_files:
        try:
            content = await fetch_file_content(user, repo_full_name, file_info["path"], branch)
            ext = os.path.splitext(file_info["path"])[1].lower()
            errors = _validate_file(content, file_info["path"])
            result.append(IngestedFile(
                filename=os.path.basename(file_info["path"]),
                path=file_info["path"],
                extension=ext,
                content=content,
                size=file_info.get("size", len(content)),
                errors=errors,
            ))
        except Exception as e:
            logger.error("github_file_error", file=file_info["path"], error=str(e))

    return result
