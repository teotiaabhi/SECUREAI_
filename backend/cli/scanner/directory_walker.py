"""Recursive directory walker for local filesystem scanning."""

import os
from typing import List, Optional, Set, Tuple

from engine.file_classifier import (
    DEFAULT_IGNORE,
    DEFAULT_IGNORE_FILES,
    SKIP_DIRECTORIES,
    SKIP_EXTENSIONS,
    classify_language,
    should_skip_file,
)
from engine.scan_scope import (
    is_excluded_directory,
    is_excluded_file,
    is_report_file,
    is_dependency_lock_file,
    detect_self_scan,
    is_test_file,
)
from cli.utils.ignore_loader import load_ignore_patterns, should_ignore, should_ignore_dir

# Hard limits to prevent accidental scanning of massive trees
MAX_FILES = 500_000
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB per file (matches engine limit)


def discover_files(
    root_path: str,
    lang_filter: Optional[Set[str]] = None,
) -> List[Tuple[str, str]]:
    """Walk directory tree and return scannable files.

    Reads .secureaiignore from the scan root (if present) and skips
    matching files and directories before scanning.

    Args:
        root_path: Absolute path to scan root (file or directory).
        lang_filter: If set, only include files matching these languages.

    Returns:
        List of (absolute_path, language) tuples for files to scan.
    """
    root_path = os.path.abspath(root_path)

    # PROBLEM 2: Detect if scanning the scanner itself
    if os.path.isdir(root_path):
        detect_self_scan(root_path)

    # Single file still respects built-in ignore defaults.
    if os.path.isfile(root_path):
        if should_skip_file(root_path):
            return []
        lang = classify_language(root_path)
        if lang is None:
            return []
        if lang_filter and lang.lower() not in lang_filter:
            return []
        return [(root_path, lang)]

    # Load .secureaiignore patterns from scan root
    ignore_rules = load_ignore_patterns(root_path)

    # Directory walk
    results: List[Tuple[str, str]] = []

    for dirpath, dirnames, filenames in os.walk(root_path, topdown=True):
        # Prune skip directories in-place for efficiency
        # 1) Engine built-in skips + hidden dirs + scan scope control
        # 2) .secureaiignore directory rules
        surviving: List[str] = []
        for d in dirnames:
            d_lower = d.lower()
            if d_lower in SKIP_DIRECTORIES or d_lower in DEFAULT_IGNORE:
                continue
            # PART 1: Scan scope directory exclusion
            if is_excluded_directory(d_lower):
                continue
            rel_dir = os.path.relpath(os.path.join(dirpath, d), root_path)
            if should_ignore_dir(d, rel_dir, ignore_rules):
                continue
            surviving.append(d)
        dirnames[:] = surviving

        for fname in filenames:
            if len(results) >= MAX_FILES:
                return results

            if fname.lower() in DEFAULT_IGNORE_FILES:
                continue

            # PART 5 + PART 9: Self-scan protection + report integrity
            if is_report_file(fname):
                continue

            # PART 1: Dependency lock file exclusion
            if is_dependency_lock_file(fname):
                continue

            # PROBLEM 3: Test file exclusion
            if is_test_file(fname):
                continue

            # PART 1: Generated file exclusion
            if is_excluded_file(fname):
                continue

            full_path = os.path.join(dirpath, fname)

            # Skip very large files
            try:
                if os.path.getsize(full_path) > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            # Use engine's skip logic
            rel_path = os.path.relpath(full_path, root_path)
            if should_skip_file(rel_path):
                continue

            # .secureaiignore file-level check
            if should_ignore(rel_path, ignore_rules, is_dir=False):
                continue

            lang = classify_language(rel_path)
            if lang is None:
                continue

            if lang_filter and lang.lower() not in lang_filter:
                continue

            results.append((full_path, lang))

    return results
