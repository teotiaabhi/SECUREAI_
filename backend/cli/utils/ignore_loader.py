"""Loader and matcher for .secureaiignore files.

Parses a .secureaiignore file (similar to .gitignore) from the scan root
and provides efficient path matching against the loaded patterns.

Supported pattern syntax:
    node_modules       — matches directory or file named "node_modules" at any depth
    dist/              — matches only directories named "dist"
    *.min.js           — matches any file ending in .min.js
    *.lock             — matches any file ending in .lock
    build/output/      — matches the exact relative path prefix
    src/test_*.py      — matches wildcard in a specific directory
    # comment          — ignored
    (blank lines)      — ignored
"""

import fnmatch
import os
from typing import List, NamedTuple, Set, Tuple

IGNORE_FILENAME = ".secureaiignore"


class _IgnoreRule(NamedTuple):
    """A single parsed ignore rule."""
    pattern: str        # The raw/normalised pattern
    dir_only: bool      # True if pattern ended with '/' (only match directories)
    anchored: bool      # True if pattern contains '/' (match from root, not any depth)


def load_ignore_patterns(root_path: str) -> List[_IgnoreRule]:
    """Read .secureaiignore from *root_path* and return parsed rules.

    Args:
        root_path: Absolute path to the scan root directory.

    Returns:
        List of _IgnoreRule.  Empty list if the file doesn't exist.
    """
    ignore_file = os.path.join(os.path.abspath(root_path), IGNORE_FILENAME)
    if not os.path.isfile(ignore_file):
        return []

    rules: List[_IgnoreRule] = []
    try:
        with open(ignore_file, "r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                # Skip blanks and comments
                if not line or line.startswith("#"):
                    continue

                dir_only = line.endswith("/")
                pattern = line.rstrip("/")

                # A pattern containing '/' is anchored to the root
                anchored = "/" in pattern

                rules.append(_IgnoreRule(
                    pattern=pattern,
                    dir_only=dir_only,
                    anchored=anchored,
                ))
    except (OSError, IOError):
        return []

    return rules


def _match_pattern(pattern: str, candidate: str) -> bool:
    """fnmatch-based match with support for ** recursive glob."""
    return fnmatch.fnmatch(candidate, pattern)


def should_ignore(rel_path: str, rules: List[_IgnoreRule], is_dir: bool = False) -> bool:
    """Check whether *rel_path* should be ignored.

    Args:
        rel_path: Path relative to scan root (forward-slash normalised).
        rules: Parsed ignore rules from load_ignore_patterns().
        is_dir: True when checking a directory entry.

    Returns:
        True if the path matches any ignore rule.
    """
    if not rules:
        return False

    # Normalise separators
    rel_path = rel_path.replace("\\", "/").strip("/")

    for rule in rules:
        # dir_only rules skip file entries
        if rule.dir_only and not is_dir:
            continue

        if rule.anchored:
            # Anchored: match against the full relative path (or as prefix for dirs)
            if _match_pattern(rule.pattern, rel_path):
                return True
            # Also match if rel_path starts with pattern/ (subtree)
            if is_dir and rel_path.startswith(rule.pattern + "/"):
                return True
            # Match parent directory components
            if rel_path.startswith(rule.pattern + "/"):
                return True
        else:
            # Un-anchored: match against the basename OR any path component
            basename = rel_path.rsplit("/", 1)[-1]
            if _match_pattern(rule.pattern, basename):
                return True
            # Also check each path segment for directory patterns
            if is_dir or rule.dir_only:
                for part in rel_path.split("/"):
                    if _match_pattern(rule.pattern, part):
                        return True
            # Check full path too (e.g. "vendor/cache" as unanchored)
            if _match_pattern(rule.pattern, rel_path):
                return True

    return False


def should_ignore_dir(dirname: str, rel_dir_path: str, rules: List[_IgnoreRule]) -> bool:
    """Convenience: check if a directory should be pruned during os.walk.

    Args:
        dirname: The directory's basename (e.g. "node_modules").
        rel_dir_path: Relative path from scan root to this directory.
        rules: Parsed ignore rules.

    Returns:
        True if the directory matches any ignore rule.
    """
    return should_ignore(rel_dir_path, rules, is_dir=True)
