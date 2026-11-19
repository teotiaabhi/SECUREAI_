"""
Context-aware rule precondition evaluator.

Evaluates rule preconditions BEFORE running expensive regex patterns.
This is the key false-positive reduction layer — rules that don't match
the project context or file context are skipped entirely.

Pipeline position:
    File Discovery → Framework Detection → **Precondition Check** → Pattern Match

Precondition types:
    1. file_types      — rule only runs on files with matching extensions
    2. file_paths      — rule only runs on files matching path patterns
    3. framework       — rule only runs when framework detected in project
    4. language        — rule only runs for matching file language
    5. not_file_paths  — rule is suppressed for files matching patterns
    6. not_contexts    — rule is suppressed when safe patterns are in scope
"""

import fnmatch
import logging
import os
import re
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from engine.framework_detector import ProjectContext

logger = logging.getLogger("engine.rule_preconditions")


# ─── Precondition Data ───────────────────────────────────────────────

class RulePreconditions:
    """Parsed preconditions from rule YAML `requires:` and `context:` blocks.

    Stored on EngineRule and evaluated by the worker before pattern matching.
    """

    __slots__ = (
        "file_types",
        "file_path_patterns",
        "not_file_path_patterns",
        "required_frameworks",
        "required_language",
        "not_contexts",
        "required_file_content",
        "exclude_educational",
        "route_decorator",
        "database_query",
    )

    def __init__(
        self,
        file_types: Optional[Tuple[str, ...]] = None,
        file_path_patterns: Optional[Tuple[str, ...]] = None,
        not_file_path_patterns: Optional[Tuple[str, ...]] = None,
        required_frameworks: Optional[Tuple[str, ...]] = None,
        required_language: Optional[str] = None,
        not_contexts: Optional[Tuple[str, ...]] = None,
        required_file_content: Optional[Tuple[str, ...]] = None,
        exclude_educational: bool = False,
        route_decorator: bool = False,
        database_query: bool = False,
    ):
        self.file_types = file_types
        self.file_path_patterns = file_path_patterns
        self.not_file_path_patterns = not_file_path_patterns
        self.required_frameworks = required_frameworks
        self.required_language = required_language
        self.not_contexts = not_contexts
        self.required_file_content = required_file_content
        self.exclude_educational = exclude_educational
        self.route_decorator = route_decorator
        self.database_query = database_query

    def to_tuple(self) -> tuple:
        """Serialize to a picklable tuple for EngineRule storage."""
        return (
            self.file_types,
            self.file_path_patterns,
            self.not_file_path_patterns,
            self.required_frameworks,
            self.required_language,
            self.not_contexts,
            self.required_file_content,
            self.exclude_educational,
            self.route_decorator,
            self.database_query,
        )

    @classmethod
    def from_tuple(cls, t: tuple) -> "RulePreconditions":
        """Reconstruct from tuple."""
        if not t or len(t) < 8:
            return cls()
        return cls(
            file_types=t[0],
            file_path_patterns=t[1],
            not_file_path_patterns=t[2],
            required_frameworks=t[3],
            required_language=t[4],
            not_contexts=t[5],
            required_file_content=t[6],
            exclude_educational=t[7],
            route_decorator=t[8] if len(t) > 8 else False,
            database_query=t[9] if len(t) > 9 else False,
        )

    def is_empty(self) -> bool:
        """Returns True if no preconditions are set."""
        return (
            self.file_types is None
            and self.file_path_patterns is None
            and self.not_file_path_patterns is None
            and self.required_frameworks is None
            and self.required_language is None
            and self.not_contexts is None
            and self.required_file_content is None
            and not self.exclude_educational
            and not self.route_decorator
            and not self.database_query
        )


# ─── Educational / Example Code Detection ────────────────────────────

# Patterns indicating educational/example/remediation code
EDUCATIONAL_PATH_PATTERNS: Tuple[str, ...] = (
    "*/examples/*",
    "*/example/*",
    "*/docs/*",
    "*/documentation/*",
    "*/tutorials/*",
    "*/tutorial/*",
    "*/samples/*",
    "*/sample/*",
    "*/demo/*",
    "*/demos/*",
    "*/templates/remediation*",
    "*/remediation_*",
    "*_example.*",
    "*_sample.*",
    "*_demo.*",
    "*/learning/*",
    "*/training/*",
)

EDUCATIONAL_CONTENT_MARKERS: Tuple[str, ...] = (
    "# example",
    "# this is an example",
    "# vulnerable example",
    "# insecure example",
    "# bad practice",
    "# do not use in production",
    "# for educational purposes",
    "# demonstration only",
    "secure_code_python",
    "vulnerable_code_python",
    "real_world_exploit",
    "fix_explanation",
    "remediation_template",
    "CWE_DEEP_KNOWLEDGE",
    "EDUCATIONAL_CONTENT",
)

# Test file patterns
TEST_PATH_PATTERNS: Tuple[str, ...] = (
    "*/tests/*",
    "*/test/*",
    "*/test_*",
    "*_test.*",
    "*_test_*",
    "*/spec/*",
    "*_spec.*",
    "*/fixtures/*",
    "*/conftest.*",
    "*/__tests__/*",
    "*/testing/*",
)


def _is_educational_file(file_name: str, content_lower: Optional[str] = None) -> bool:
    """Check if a file is educational/example code."""
    normalized = file_name.replace("\\", "/").lower()

    for pattern in EDUCATIONAL_PATH_PATTERNS:
        if fnmatch.fnmatch(normalized, pattern):
            return True

    if content_lower:
        marker_count = sum(
            1 for m in EDUCATIONAL_CONTENT_MARKERS if m.lower() in content_lower
        )
        # Need at least 2 markers to flag as educational
        if marker_count >= 2:
            return True

    return False


def _is_test_file(file_name: str) -> bool:
    """Check if a file is a test file."""
    normalized = file_name.replace("\\", "/").lower()
    for pattern in TEST_PATH_PATTERNS:
        if fnmatch.fnmatch(normalized, pattern):
            return True
    return False


# ─── Precondition Evaluation ─────────────────────────────────────────

def evaluate_preconditions(
    preconditions: RulePreconditions,
    file_name: str,
    file_language: str,
    project_context: Optional[ProjectContext] = None,
    content_lower: Optional[str] = None,
) -> Tuple[bool, str]:
    """Evaluate rule preconditions against current file context.

    Returns:
        (should_run, reason) — True if rule should run, False to skip.
        `reason` explains why the rule was skipped.
    """
    if preconditions.is_empty():
        return True, ""

    normalized_path = file_name.replace("\\", "/").lower()
    _, ext = os.path.splitext(file_name)
    ext_lower = ext.lower()

    # 1) File type restriction
    if preconditions.file_types:
        allowed = {ft.lower() if ft.startswith(".") else f".{ft.lower()}"
                   for ft in preconditions.file_types}
        if ext_lower not in allowed:
            return False, f"file_type:{ext_lower} not in {allowed}"

    # 2) File path patterns (must match at least one)
    if preconditions.file_path_patterns:
        matched = False
        for pattern in preconditions.file_path_patterns:
            if fnmatch.fnmatch(normalized_path, pattern.lower()):
                matched = True
                break
        if not matched:
            return False, f"file_path:{normalized_path} didn't match required patterns"

    # 3) Excluded file paths
    if preconditions.not_file_path_patterns:
        for pattern in preconditions.not_file_path_patterns:
            if fnmatch.fnmatch(normalized_path, pattern.lower()):
                return False, f"file_path:{normalized_path} matched exclusion {pattern}"

    # 4) Required frameworks (project-level)
    if preconditions.required_frameworks and project_context:
        if not any(
            project_context.has_framework(fw)
            for fw in preconditions.required_frameworks
        ):
            return False, (
                f"framework:{preconditions.required_frameworks} "
                f"not detected (found: {list(project_context.frameworks)})"
            )

    # 5) Language check
    if preconditions.required_language:
        if file_language.lower() != preconditions.required_language.lower():
            return False, f"language:{file_language} != {preconditions.required_language}"

    # 6) Suppress in educational/example code
    if preconditions.exclude_educational:
        if _is_educational_file(file_name, content_lower):
            return False, "educational/example code detected"

    # 7) Required file content (at least one pattern must be in file)
    if preconditions.required_file_content and content_lower:
        found = any(
            pat.lower() in content_lower
            for pat in preconditions.required_file_content
        )
        if not found:
            return False, f"required content patterns not found in file"

    # 8) Not-contexts (safe patterns suppress rule)
    if preconditions.not_contexts and content_lower:
        for pattern in preconditions.not_contexts:
            if pattern.lower() in content_lower:
                return False, f"safe context detected: {pattern}"

    return True, ""


def parse_preconditions_from_rule_dict(rule_dict: dict) -> RulePreconditions:
    """Parse preconditions from a YAML rule dictionary.

    Supports the new `requires:` block format:
        requires:
            language: python
            framework: [fastapi, flask]
            file_types: [".py"]
            file_paths: ["*/api/*"]
            not_file_paths: ["*/tests/*", "*/examples/*"]
            not_contexts: ["parameterized query with %s"]
            required_content: ["import fastapi"]
            exclude_educational: true
    """
    requires = rule_dict.get("requires", {})
    if not requires:
        return RulePreconditions()

    # file_types
    ft = requires.get("file_types")
    file_types = tuple(ft) if isinstance(ft, list) else None

    # file_paths
    fp = requires.get("file_paths")
    file_path_patterns = tuple(fp) if isinstance(fp, list) else None

    # not_file_paths
    nfp = requires.get("not_file_paths")
    not_file_path_patterns = tuple(nfp) if isinstance(nfp, list) else None

    # framework (string or list)
    fw = requires.get("framework")
    if isinstance(fw, str):
        required_frameworks = (fw,)
    elif isinstance(fw, list):
        required_frameworks = tuple(fw)
    else:
        required_frameworks = None

    # language override
    lang = requires.get("language")
    required_language = lang if isinstance(lang, str) else None

    # not_contexts
    nc = requires.get("not_contexts")
    not_contexts = tuple(nc) if isinstance(nc, list) else None

    # required_content
    rc = requires.get("required_content")
    required_file_content = tuple(rc) if isinstance(rc, list) else None

    # exclude_educational
    ee = requires.get("exclude_educational", False)

    # Context-aware signal requirements (multi-signal detection)
    route_decorator = bool(requires.get("route_decorator", False))
    database_query = bool(requires.get("database_query", False))

    return RulePreconditions(
        file_types=file_types,
        file_path_patterns=file_path_patterns,
        not_file_path_patterns=not_file_path_patterns,
        required_frameworks=required_frameworks,
        required_language=required_language,
        not_contexts=not_contexts,
        required_file_content=required_file_content,
        exclude_educational=bool(ee),
        route_decorator=route_decorator,
        database_query=database_query,
    )
