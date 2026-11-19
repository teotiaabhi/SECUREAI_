"""
Scan Scope Control — strict filtering to prevent noise from non-source files.

This module enforces what files should NEVER be scanned and ensures only
real source code enters the scanning pipeline. It provides both path-level
exclusions and a self-scan protection mechanism.

Pipeline position: BEFORE file discovery / ingestion

PART 1 — Scan Scope Control
PART 5 — Self-scan Protection
PART 9 — Report Integrity Protection
"""

import logging
import os
from pathlib import PurePosixPath
from typing import FrozenSet, Set

logger = logging.getLogger("engine.scan_scope")

# ─── Directories that must NEVER be scanned ──────────────────────────

EXCLUDED_DIRECTORIES: FrozenSet[str] = frozenset({
    # Dependency directories
    "node_modules",
    "bower_components",
    "jspm_packages",
    # Build / output
    "dist",
    "build",
    ".next",
    "out",
    "target",
    "bin",
    "obj",
    # Coverage / test artifacts
    "coverage",
    ".nyc_output",
    "htmlcov",
    # VCS
    ".git",
    ".svn",
    ".hg",
    # Python
    "__pycache__",
    "venv",
    ".venv",
    "env",
    ".eggs",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    # IDE
    ".idea",
    ".vscode",
    ".vs",
    # Caches
    ".cache",
    ".parcel-cache",
    ".turbo",
    ".gradle",
    ".mvn",
    # Vendor
    "vendor",
    # Test / example directories (PROBLEM 3)
    "rule-tests",
    "examples",
    "learning",
})

# ─── Scanner internal directories (self-scan protection) ────────────
# These directories are excluded ONLY when a self-scan marker is detected.

SCANNER_INTERNAL_DIRECTORIES: FrozenSet[str] = frozenset({
    "engine",
    "rules",
    "cli",
    "scanner",
})

# Marker files that confirm a directory is the SecureAI scanner itself
SCANNER_MARKER_FILES: FrozenSet[str] = frozenset({
    "detection_engine.py",
    "rule_loader.py",
    "pipeline.py",
    "streaming_scanner.py",
})

# ─── Files that must NEVER be scanned ────────────────────────────────

EXCLUDED_FILES: FrozenSet[str] = frozenset({
    # Scanner output (self-scan protection)
    "secureai-report.json",
    # Dependency lock files
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.lock",
    "pipfile.lock",
    "gemfile.lock",
    "cargo.lock",
    "poetry.lock",
    "go.sum",
    # Environment files
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.test",
})

# ─── File patterns that indicate generated / scanner output ──────────

GENERATED_FILE_PATTERNS: FrozenSet[str] = frozenset({
    "secureai-report",
    "-report.json",
    "-results.json",
    "scan-output",
    "scan-results",
})

# ─── Extensions that should never be scanned ─────────────────────────

EXCLUDED_EXTENSIONS: FrozenSet[str] = frozenset({
    ".lock",
    ".min.js",
    ".min.css",
    ".map",
    ".chunk.js",
    ".bundle.js",
    ".d.ts",
    ".snap",
    ".wasm",
    # Binary
    ".exe", ".dll", ".so", ".dylib", ".pyc", ".pyo",
    ".class", ".o", ".obj", ".a", ".lib",
    # Images
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".webp",
    # Media
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    # Documents
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    # Archives
    ".zip", ".tar", ".gz", ".rar", ".7z",
    # Fonts
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
})


# ─── Test file patterns ───────────────────────────────────────────────

TEST_FILE_PATTERNS: FrozenSet[str] = frozenset({
    "test_",
    "_test.",
    ".test.",
    "spec_",
    "_spec.",
    ".spec.",
    "conftest.",
})

TEST_DIRECTORY_NAMES: FrozenSet[str] = frozenset({
    "tests",
    "test",
    "__tests__",
    "spec",
    "specs",
    "fixtures",
    "testing",
    "rule-tests",
    "examples",
    "learning",
})


def is_test_file(file_name: str) -> bool:
    """Check if a file is a test file that should be excluded from scanning.

    Matches:
    - test_*.py, *_test.py, *.test.js, *.spec.ts, conftest.py
    - Files inside tests/, __tests__/, spec/, rule-tests/ etc.
    """
    basename = PurePosixPath(file_name.replace("\\", "/")).name.lower()
    for pattern in TEST_FILE_PATTERNS:
        if pattern in basename:
            return True
    return False


def is_test_directory(dir_name: str) -> bool:
    """Check if a directory is a test directory."""
    return dir_name.lower() in TEST_DIRECTORY_NAMES


# ─── Self-Scan Detection ─────────────────────────────────────────────

_is_self_scan: bool = False


def detect_self_scan(scan_root: str) -> bool:
    """Detect if the scan target is the SecureAI scanner itself.

    Checks for the presence of scanner marker files in the scan root
    or in an 'engine/' subdirectory. When detected, scanner internal
    directories will be excluded from scanning.

    Call this once at scan start.
    """
    global _is_self_scan

    engine_dir = os.path.join(scan_root, "engine")
    if os.path.isdir(engine_dir):
        try:
            contents = set(os.listdir(engine_dir))
            if contents & SCANNER_MARKER_FILES:
                _is_self_scan = True
                logger.info(
                    "Self-scan detected: excluding scanner internal directories "
                    "(%s)", ", ".join(sorted(SCANNER_INTERNAL_DIRECTORIES)),
                )
                return True
        except OSError:
            pass

    _is_self_scan = False
    return False


def is_scanner_internal_directory(dir_name: str) -> bool:
    """Check if a directory is part of the scanner's own codebase.

    Only returns True when self-scan has been detected.
    """
    if not _is_self_scan:
        return False
    return dir_name.lower() in SCANNER_INTERNAL_DIRECTORIES


def is_excluded_directory(dir_name: str) -> bool:
    """Check if a directory name should be excluded from scanning."""
    d_lower = dir_name.lower()
    if d_lower in EXCLUDED_DIRECTORIES:
        return True
    if is_scanner_internal_directory(dir_name):
        return True
    if is_test_directory(dir_name):
        return True
    return False


def is_excluded_file(file_name: str) -> bool:
    """Check if a file should be excluded from scanning.

    Checks:
    1. Exact filename match against EXCLUDED_FILES
    2. Generated file patterns (scanner output)
    3. File extension exclusions
    4. Test file patterns (PROBLEM 3)
    """
    basename = PurePosixPath(file_name.replace("\\", "/")).name.lower()

    # Exact match
    if basename in EXCLUDED_FILES:
        return True

    # Generated file patterns (self-scan protection)
    for pattern in GENERATED_FILE_PATTERNS:
        if pattern in basename:
            return True

    # Test file patterns (PROBLEM 3)
    if is_test_file(basename):
        return True

    # Extension check
    ext = _get_extension(basename)
    if ext in EXCLUDED_EXTENSIONS:
        return True

    return False


def is_report_file(file_path: str) -> bool:
    """Self-scan protection: detect if a file is a scanner report.

    Prevents recursive scanning of SecureAI's own output.
    """
    basename = PurePosixPath(file_path.replace("\\", "/")).name.lower()

    # Direct report file detection
    if basename == "secureai-report.json":
        return True

    # Pattern-based detection for custom report paths
    if basename.endswith("-report.json") or basename.endswith("-results.json"):
        return True

    return False


def is_dependency_lock_file(file_path: str) -> bool:
    """Check if a file is a dependency lock file that should not be scanned."""
    basename = PurePosixPath(file_path.replace("\\", "/")).name.lower()
    lock_files = {
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "composer.lock", "pipfile.lock", "gemfile.lock",
        "cargo.lock", "poetry.lock", "go.sum",
    }
    return basename in lock_files


def should_exclude_path(file_path: str) -> bool:
    """Master exclusion check: returns True if the file should NOT be scanned.

    Combines all scope control checks:
    1. Directory exclusions (including scanner-internal + test dirs)
    2. File exclusions (including test files)
    3. Self-scan protection
    4. Report integrity protection
    """
    path_lower = file_path.replace("\\", "/").lower()
    parts = path_lower.split("/")

    # Check directory components
    for part in parts[:-1]:  # all except the filename
        if part in EXCLUDED_DIRECTORIES:
            return True
        # PROBLEM 2: Scanner internal directory exclusion
        if _is_self_scan and part in SCANNER_INTERNAL_DIRECTORIES:
            return True
        # PROBLEM 3: Test directory exclusion
        if part in TEST_DIRECTORY_NAMES:
            return True

    # Check the file itself
    basename = parts[-1] if parts else ""

    if basename in EXCLUDED_FILES:
        return True

    if is_report_file(file_path):
        return True

    if is_dependency_lock_file(file_path):
        return True

    # PROBLEM 3: Test file exclusion
    if is_test_file(basename):
        return True

    ext = _get_extension(basename)
    if ext in EXCLUDED_EXTENSIONS:
        return True

    # Generated file patterns
    for pattern in GENERATED_FILE_PATTERNS:
        if pattern in basename:
            return True

    return False


def filter_scan_targets(
    file_paths: list,
    report_output_path: str = "",
) -> list:
    """Filter a list of file paths, removing all excluded files.

    Also excludes the report output path itself to prevent self-scanning.

    Args:
        file_paths: List of file paths to filter.
        report_output_path: The path where the report will be written.

    Returns:
        Filtered list with only scannable source files.
    """
    excluded_count = 0
    result = []

    # Normalize the report output path for comparison
    report_basename = ""
    if report_output_path:
        report_basename = os.path.basename(report_output_path).lower()

    for path in file_paths:
        # Exclude the report output file itself
        if report_basename and os.path.basename(path).lower() == report_basename:
            excluded_count += 1
            continue

        if should_exclude_path(path):
            excluded_count += 1
            continue

        result.append(path)

    if excluded_count:
        logger.info(
            "Scan scope control: excluded %d files, %d remain.",
            excluded_count, len(result),
        )

    return result


def _get_extension(filename: str) -> str:
    """Extract file extension."""
    dot_pos = filename.rfind(".")
    if dot_pos > 0:
        return filename[dot_pos:]
    return ""
