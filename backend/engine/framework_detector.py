"""
Project-level framework and context detector.

Scans the project root for framework indicators (package.json, requirements.txt,
go.mod, pom.xml, etc.) and builds a ProjectContext that rules can use as
preconditions. Runs ONCE before scanning begins and is shared across all workers.

This is the foundation for context-aware rule activation — rules can declare
`requires.framework: fastapi` and will only fire when FastAPI is actually detected.
"""

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger("engine.framework_detector")


# ─── Framework Indicator Definitions ─────────────────────────────────

@dataclass(frozen=True)
class FrameworkIndicator:
    """Defines how to detect a framework in a project."""
    name: str                        # e.g. "fastapi", "django", "nextjs"
    ecosystem: str                   # e.g. "python", "javascript", "java"
    # Files whose presence indicates this framework
    marker_files: Tuple[str, ...] = ()
    # Patterns to search in dependency manifests
    dependency_patterns: Tuple[Tuple[str, str], ...] = ()  # (file_glob, regex)
    # Import patterns found in source code
    import_patterns: Tuple[str, ...] = ()


# Python frameworks
_PYTHON_FRAMEWORKS = [
    FrameworkIndicator(
        name="fastapi",
        ecosystem="python",
        dependency_patterns=(
            ("requirements*.txt", r"(?i)^fastapi\b"),
            ("setup.py", r"fastapi"),
            ("setup.cfg", r"fastapi"),
            ("pyproject.toml", r"fastapi"),
            ("Pipfile", r"fastapi"),
        ),
        import_patterns=("from fastapi", "import fastapi"),
    ),
    FrameworkIndicator(
        name="django",
        ecosystem="python",
        marker_files=("manage.py",),
        dependency_patterns=(
            ("requirements*.txt", r"(?i)^django\b"),
            ("setup.py", r"django"),
            ("pyproject.toml", r"django"),
            ("Pipfile", r"django"),
        ),
        import_patterns=("from django", "import django"),
    ),
    FrameworkIndicator(
        name="flask",
        ecosystem="python",
        dependency_patterns=(
            ("requirements*.txt", r"(?i)^flask\b"),
            ("setup.py", r"flask"),
            ("pyproject.toml", r"flask"),
            ("Pipfile", r"flask"),
        ),
        import_patterns=("from flask", "import flask"),
    ),
    FrameworkIndicator(
        name="tornado",
        ecosystem="python",
        dependency_patterns=(
            ("requirements*.txt", r"(?i)^tornado\b"),
        ),
        import_patterns=("import tornado", "from tornado"),
    ),
    FrameworkIndicator(
        name="sqlalchemy",
        ecosystem="python",
        dependency_patterns=(
            ("requirements*.txt", r"(?i)^sqlalchemy\b"),
        ),
        import_patterns=("from sqlalchemy", "import sqlalchemy"),
    ),
]

# JavaScript frameworks
_JS_FRAMEWORKS = [
    FrameworkIndicator(
        name="nextjs",
        ecosystem="javascript",
        marker_files=("next.config.js", "next.config.mjs", "next.config.ts"),
        dependency_patterns=(
            ("package.json", r'"next"\s*:'),
        ),
    ),
    FrameworkIndicator(
        name="express",
        ecosystem="javascript",
        dependency_patterns=(
            ("package.json", r'"express"\s*:'),
        ),
        import_patterns=(
            'require("express")',
            "require('express')",
            "from 'express'",
            'from "express"',
        ),
    ),
    FrameworkIndicator(
        name="react",
        ecosystem="javascript",
        dependency_patterns=(
            ("package.json", r'"react"\s*:'),
        ),
    ),
    FrameworkIndicator(
        name="angular",
        ecosystem="javascript",
        marker_files=("angular.json",),
        dependency_patterns=(
            ("package.json", r'"@angular/core"\s*:'),
        ),
    ),
    FrameworkIndicator(
        name="vue",
        ecosystem="javascript",
        dependency_patterns=(
            ("package.json", r'"vue"\s*:'),
        ),
    ),
]

# Java frameworks
_JAVA_FRAMEWORKS = [
    FrameworkIndicator(
        name="spring",
        ecosystem="java",
        dependency_patterns=(
            ("pom.xml", r"spring-boot"),
            ("build.gradle", r"org\.springframework"),
            ("build.gradle.kts", r"org\.springframework"),
        ),
        import_patterns=("import org.springframework",),
    ),
    FrameworkIndicator(
        name="struts",
        ecosystem="java",
        dependency_patterns=(
            ("pom.xml", r"org\.apache\.struts"),
        ),
        import_patterns=("import org.apache.struts",),
    ),
]

# PHP frameworks
_PHP_FRAMEWORKS = [
    FrameworkIndicator(
        name="laravel",
        ecosystem="php",
        marker_files=("artisan",),
        dependency_patterns=(
            ("composer.json", r'"laravel/framework"'),
        ),
        import_patterns=("use Illuminate",),
    ),
    FrameworkIndicator(
        name="symfony",
        ecosystem="php",
        dependency_patterns=(
            ("composer.json", r'"symfony/'),
        ),
        import_patterns=("use Symfony",),
    ),
]

# Ruby frameworks
_RUBY_FRAMEWORKS = [
    FrameworkIndicator(
        name="rails",
        ecosystem="ruby",
        marker_files=("Gemfile",),
        dependency_patterns=(
            ("Gemfile", r"gem\s+['\"]rails['\"]"),
        ),
        import_patterns=("Rails.application",),
    ),
]

# Go frameworks
_GO_FRAMEWORKS = [
    FrameworkIndicator(
        name="gin",
        ecosystem="go",
        dependency_patterns=(
            ("go.mod", r"github\.com/gin-gonic/gin"),
        ),
        import_patterns=("github.com/gin-gonic/gin",),
    ),
    FrameworkIndicator(
        name="echo",
        ecosystem="go",
        dependency_patterns=(
            ("go.mod", r"github\.com/labstack/echo"),
        ),
    ),
]

ALL_INDICATORS = (
    _PYTHON_FRAMEWORKS
    + _JS_FRAMEWORKS
    + _JAVA_FRAMEWORKS
    + _PHP_FRAMEWORKS
    + _RUBY_FRAMEWORKS
    + _GO_FRAMEWORKS
)


# ─── Dependency Manifest Detection ───────────────────────────────────

DEPENDENCY_MANIFESTS: FrozenSet[str] = frozenset({
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    "Cargo.toml",
    "Cargo.lock",
    "mix.exs",
    "pubspec.yaml",
    "*.csproj",
    "*.sln",
})


def is_dependency_manifest(file_name: str) -> bool:
    """Check if a file is a dependency manifest.

    Dependency-confusion rules should ONLY run on these files.
    """
    base = os.path.basename(file_name).lower()
    # Exact match
    if base in {m.lower() for m in DEPENDENCY_MANIFESTS if not m.startswith("*")}:
        return True
    # Glob patterns (e.g. *.csproj)
    for pattern in DEPENDENCY_MANIFESTS:
        if pattern.startswith("*"):
            ext = pattern[1:]  # e.g. ".csproj"
            if base.endswith(ext.lower()):
                return True
    # requirements-*.txt pattern
    if base.startswith("requirements") and base.endswith(".txt"):
        return True
    return False


# ─── Project Context ─────────────────────────────────────────────────

@dataclass
class ProjectContext:
    """Aggregated project-level context built during discovery phase.

    Shared across all worker processes via serialization. Workers use it
    to evaluate rule preconditions before running patterns.
    """
    # Detected frameworks (lowercased names)
    frameworks: FrozenSet[str] = field(default_factory=frozenset)
    # Detected languages (from file extensions)
    languages: FrozenSet[str] = field(default_factory=frozenset)
    # Ecosystem (python, javascript, java, etc.)
    ecosystems: FrozenSet[str] = field(default_factory=frozenset)
    # Dependency manifest files found in project
    manifest_files: FrozenSet[str] = field(default_factory=frozenset)
    # Whether this is a multi-tenant app (heuristic)
    has_tenant_patterns: bool = False
    # Whether auth/session management found
    has_auth_patterns: bool = False
    # Project root path
    root_path: str = ""

    def has_framework(self, name: str) -> bool:
        return name.lower() in self.frameworks

    def has_any_framework(self, *names: str) -> bool:
        return any(n.lower() in self.frameworks for n in names)

    def to_dict(self) -> dict:
        return {
            "frameworks": list(self.frameworks),
            "languages": list(self.languages),
            "ecosystems": list(self.ecosystems),
            "manifest_files": list(self.manifest_files),
            "has_tenant_patterns": self.has_tenant_patterns,
            "has_auth_patterns": self.has_auth_patterns,
            "root_path": self.root_path,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ProjectContext":
        return cls(
            frameworks=frozenset(d.get("frameworks", [])),
            languages=frozenset(d.get("languages", [])),
            ecosystems=frozenset(d.get("ecosystems", [])),
            manifest_files=frozenset(d.get("manifest_files", [])),
            has_tenant_patterns=d.get("has_tenant_patterns", False),
            has_auth_patterns=d.get("has_auth_patterns", False),
            root_path=d.get("root_path", ""),
        )


# ─── Detection Logic ─────────────────────────────────────────────────

def _read_file_safe(path: str, max_size: int = 512_000) -> Optional[str]:
    """Read a file, returning None if it fails or exceeds size limit."""
    try:
        if os.path.getsize(path) > max_size:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except (OSError, IOError):
        return None


def _check_dependency_file(
    root: str,
    file_glob: str,
    regex: str,
) -> bool:
    """Check if a dependency pattern matches in target files under root."""
    import fnmatch
    try:
        compiled = re.compile(regex, re.MULTILINE)
    except re.error:
        return False

    for entry in os.listdir(root):
        if fnmatch.fnmatch(entry.lower(), file_glob.lower()):
            content = _read_file_safe(os.path.join(root, entry))
            if content and compiled.search(content):
                return True
    return False


def detect_project_context(
    root_path: str,
    file_list: Optional[List[Tuple[str, str]]] = None,
) -> ProjectContext:
    """Detect frameworks, ecosystems, and project characteristics.

    Args:
        root_path: Absolute path to project root directory.
        file_list: Optional pre-discovered list of (file_path, language) tuples.

    Returns:
        ProjectContext with detected frameworks and metadata.
    """
    root = os.path.abspath(root_path)
    detected_frameworks: Set[str] = set()
    detected_ecosystems: Set[str] = set()
    detected_languages: Set[str] = set()
    found_manifests: Set[str] = set()

    # Collect languages from file list
    if file_list:
        for _, lang in file_list:
            detected_languages.add(lang.lower())

    # Check project root for manifests
    try:
        root_files = os.listdir(root)
    except OSError:
        root_files = []

    for fname in root_files:
        if is_dependency_manifest(fname):
            found_manifests.add(fname)

    # Detect frameworks via indicators
    for indicator in ALL_INDICATORS:
        found = False

        # Check marker files
        for marker in indicator.marker_files:
            if marker.lower() in {f.lower() for f in root_files}:
                found = True
                break

        # Check dependency patterns
        if not found:
            for file_glob, regex in indicator.dependency_patterns:
                if _check_dependency_file(root, file_glob, regex):
                    found = True
                    break

        if found:
            detected_frameworks.add(indicator.name)
            detected_ecosystems.add(indicator.ecosystem)

    # Heuristic: detect multi-tenant patterns
    has_tenant = False
    has_auth = False
    if file_list:
        sample_count = 0
        for fpath, lang in file_list:
            if sample_count > 50:
                break
            if lang.lower() not in ("python", "javascript", "typescript", "java"):
                continue
            content = _read_file_safe(fpath, max_size=100_000)
            if not content:
                continue
            sample_count += 1
            content_lower = content.lower()
            if any(p in content_lower for p in ("tenant_id", "org_id", "organization_id", "team_id")):
                has_tenant = True
            if any(p in content_lower for p in (
                "get_current_user", "current_user", "@login_required",
                "depends(get_current", "jwt", "bearer", "authorization"
            )):
                has_auth = True

    ctx = ProjectContext(
        frameworks=frozenset(detected_frameworks),
        languages=frozenset(detected_languages),
        ecosystems=frozenset(detected_ecosystems),
        manifest_files=frozenset(found_manifests),
        has_tenant_patterns=has_tenant,
        has_auth_patterns=has_auth,
        root_path=root,
    )

    logger.info(
        "Project context detected: frameworks=%s, ecosystems=%s, "
        "languages=%d, manifests=%d, multi_tenant=%s, auth=%s",
        list(ctx.frameworks), list(ctx.ecosystems),
        len(ctx.languages), len(ctx.manifest_files),
        ctx.has_tenant_patterns, ctx.has_auth_patterns,
    )

    return ctx
