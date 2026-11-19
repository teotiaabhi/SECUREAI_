"""Test sample loader for the rule validation framework.

Discovers test sample files, parses structured header comments to extract
metadata, and returns a queryable TestSuite.
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Regex patterns for extracting metadata from header comment blocks.
# Supports both ``#``-style and ``//``-style comments.
# Matches both ``@key: value`` and plain ``key: value`` in comment headers.
_HEADER_LINE_RE = re.compile(r"^\s*(?:#|//)\s*(.+)$", re.MULTILINE)
_META_KV_RE = re.compile(
    r"^\s*(?:#|//|[\s*]*)\s*@?(\w[\w_-]*)\s*:\s+(.+?)\s*$", re.MULTILINE
)

# Recognised file extensions mapped to language names.
_EXT_TO_LANGUAGE: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".cpp": "cpp",
    ".rs": "rust",
    ".sql": "sql",
    ".sh": "bash",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".xml": "xml",
    ".html": "html",
}


@dataclass
class TestCase:
    """A single test sample with its expected behaviour.

    Attributes:
        file_path: Absolute path to the test sample file.
        content: Full text content of the file.
        test_type: Either ``positive`` (should trigger rules) or ``negative``
            (should **not** trigger rules).
        expected_rule_ids: Rule identifiers expected to fire (positive) or
            expected to stay silent (negative).
        category: Security category the test belongs to.
        language: Programming language of the sample.
        file_size_bytes: Size of the file in bytes.
    """

    file_path: Path
    content: str
    test_type: str
    expected_rule_ids: List[str]
    category: str
    language: str
    file_size_bytes: int


class TestSuite:
    """Collection of discovered test cases with index-based access."""

    def __init__(self) -> None:
        self._cases: List[TestCase] = []
        self._by_category: Dict[str, List[TestCase]] = {}
        self._by_type: Dict[str, List[TestCase]] = {}
        self._by_language: Dict[str, List[TestCase]] = {}

    def add(self, case: TestCase) -> None:
        """Register a test case and update internal indices."""
        self._cases.append(case)
        self._by_category.setdefault(case.category, []).append(case)
        self._by_type.setdefault(case.test_type, []).append(case)
        self._by_language.setdefault(case.language, []).append(case)

    def get_tests_by_category(self, category: str) -> List[TestCase]:
        """Return all tests in *category* (case-insensitive)."""
        return list(self._by_category.get(category.lower(), []))

    def get_tests_by_type(self, test_type: str) -> List[TestCase]:
        """Return all tests of *test_type* (``positive`` or ``negative``)."""
        return list(self._by_type.get(test_type.lower(), []))

    def get_positive_tests(self) -> List[TestCase]:
        """Convenience shortcut for ``get_tests_by_type('positive')``."""
        return self.get_tests_by_type("positive")

    def get_negative_tests(self) -> List[TestCase]:
        """Convenience shortcut for ``get_tests_by_type('negative')``."""
        return self.get_tests_by_type("negative")

    @property
    def all_tests(self) -> List[TestCase]:
        """Return every registered test case."""
        return list(self._cases)

    @property
    def categories(self) -> Set[str]:
        """Distinct categories present in the suite."""
        return set(self._by_category.keys())

    @property
    def languages(self) -> Set[str]:
        """Distinct languages present in the suite."""
        return set(self._by_language.keys())

    def __len__(self) -> int:
        return len(self._cases)

    def __repr__(self) -> str:
        pos = len(self.get_positive_tests())
        neg = len(self.get_negative_tests())
        return f"<TestSuite total={len(self)} positive={pos} negative={neg}>"


def _infer_language(file_path: Path) -> str:
    """Guess the programming language from the file extension.

    Args:
        file_path: Path to the test sample file.

    Returns:
        A normalised language string, or ``"unknown"`` when the extension is
        not recognised.
    """
    return _EXT_TO_LANGUAGE.get(file_path.suffix.lower(), "unknown")


def _parse_header_metadata(content: str) -> Dict[str, str]:
    """Extract ``@key: value`` pairs from the leading comment block.

    The parser recognises both ``#`` and ``//`` comment prefixes and stops
    at the first non-comment, non-blank line.

    Args:
        content: Full file content.

    Returns:
        Dictionary of discovered metadata keys (lowercased) to their values.
    """
    metadata: Dict[str, str] = {}

    for match in _META_KV_RE.finditer(content):
        key = match.group(1).strip().lower()
        value = match.group(2).strip()
        metadata[key] = value

        # Stop scanning after we leave the header comment block.  We allow
        # up to 1024 characters which is generous for any header block.
        if match.end() > 4096:
            break

    return metadata


def _parse_test_case(file_path: Path) -> Optional[TestCase]:
    """Read a single test sample file and return a ``TestCase``.

    Args:
        file_path: Path to the sample file.

    Returns:
        A ``TestCase`` if the file contains valid metadata, otherwise ``None``.
    """
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.error("Cannot read test file %s: %s", file_path, exc)
        return None

    meta = _parse_header_metadata(content)

    # Resolve test_type from various key conventions.
    # Files may use: @test_type, @type, or "Test: positive for rule ..."
    test_type = meta.get("test_type", meta.get("type", "")).lower()
    if test_type not in ("positive", "negative"):
        # Try the "test" key: "positive for rule JS-INJ-001" or "positive_01_innerhtml"
        raw_test = meta.get("test", "").lower()
        if raw_test.startswith("positive"):
            test_type = "positive"
        elif raw_test.startswith("negative"):
            test_type = "negative"

    if test_type not in ("positive", "negative"):
        logger.warning(
            "Test file %s has missing or invalid @test_type ('%s'); skipping.",
            file_path,
            test_type,
        )
        return None

    # Resolve expected rule IDs from various key conventions.
    raw_ids = meta.get("expected_rule_ids", meta.get("rule_ids", meta.get("rules", "")))
    if not raw_ids:
        # Try the "test" key: "positive for rule JS-INJ-001"
        raw_test = meta.get("test", "")
        rule_match = re.search(r"(?:for\s+)?rule\s+([\w-]+(?:,\s*[\w-]+)*)", raw_test, re.IGNORECASE)
        if rule_match:
            raw_ids = rule_match.group(1)
        else:
            # Try the "expected" key: "TRIGGER XSS-JS-001, XSS-REACT-001" or "should_trigger"
            raw_expected = meta.get("expected", "")
            trigger_match = re.search(
                r"TRIGGER\s+(?:rule\s+)?([\w-]+(?:,\s*[\w-]+)*)",
                raw_expected,
                re.IGNORECASE,
            )
            if trigger_match:
                raw_ids = trigger_match.group(1)

    expected_rule_ids = [rid.strip() for rid in raw_ids.split(",") if rid.strip()]

    category = meta.get("category", "uncategorized").lower()
    raw_language = meta.get("language", _infer_language(file_path)).lower()
    # Normalize language strings like "javascript (react)" or "python (flask)" to base language
    language = re.sub(r"\s*\(.*?\)\s*", "", raw_language).strip()
    # Further normalize "yaml (kubernetes)" → "yaml", "node.js" → "javascript", etc.
    _LANG_ALIASES: Dict[str, str] = {
        "node.js": "javascript", "nodejs": "javascript", "node": "javascript",
        "react": "javascript", "jsx": "javascript", "tsx": "typescript",
        "c#": "csharp", "bash": "shell",
    }
    language = _LANG_ALIASES.get(language, language)

    file_size = file_path.stat().st_size

    return TestCase(
        file_path=file_path,
        content=content,
        test_type=test_type,
        expected_rule_ids=expected_rule_ids,
        category=category,
        language=language,
        file_size_bytes=file_size,
    )


# Extensions we consider to be test sample files (source code or config).
_TEST_EXTENSIONS: Set[str] = set(_EXT_TO_LANGUAGE.keys()) | {".txt", ".json", ".conf", ".ini"}


def load_all_tests(tests_dir: Path) -> TestSuite:
    """Discover and load every test sample file under *tests_dir*.

    Files inside the ``runner`` sub-directory and hidden directories are
    excluded.  Only files with recognised source-code extensions are
    considered.

    Args:
        tests_dir: Root directory to scan.

    Returns:
        A populated ``TestSuite``.
    """
    suite = TestSuite()

    if not tests_dir.is_dir():
        logger.error("Tests directory does not exist: %s", tests_dir)
        return suite

    skipped = 0
    for candidate in sorted(tests_dir.rglob("*")):
        if not candidate.is_file():
            continue
        # Skip files that belong to the runner package itself.
        try:
            candidate.relative_to(tests_dir / "runner")
            continue
        except ValueError:
            pass
        # Skip hidden directories / files.
        if any(part.startswith(".") for part in candidate.parts):
            continue
        # Only process recognised extensions.
        if candidate.suffix.lower() not in _TEST_EXTENSIONS:
            continue

        case = _parse_test_case(candidate)
        if case is not None:
            suite.add(case)
        else:
            skipped += 1

    logger.info(
        "Loaded %d test cases from %s (%d skipped).",
        len(suite),
        tests_dir,
        skipped,
    )
    return suite
