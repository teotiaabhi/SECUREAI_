"""
Rule Context Gating — framework-aware rule activation.

Ensures rules only execute when the correct project context exists.
This prevents false positives from framework-specific rules firing
on projects that don't use those frameworks.

PART 2 — Rule Context Gating
PART 6 — File Type Filtering

Pipeline position: BEFORE pattern matching, AFTER file discovery
"""

import logging
import os
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger("engine.context_gating")


# ─── Language → Extension Mapping for File Type Filtering ────────────

LANGUAGE_EXTENSIONS: Dict[str, FrozenSet[str]] = {
    "python": frozenset({".py", ".pyw"}),
    "javascript": frozenset({".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte"}),
    "typescript": frozenset({".ts", ".tsx", ".mts"}),
    "java": frozenset({".java"}),
    "go": frozenset({".go"}),
    "rust": frozenset({".rs"}),
    "ruby": frozenset({".rb", ".erb"}),
    "php": frozenset({".php", ".phtml"}),
    "csharp": frozenset({".cs"}),
    "cpp": frozenset({".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hxx"}),
    "swift": frozenset({".swift"}),
    "kotlin": frozenset({".kt", ".kts"}),
    "sql": frozenset({".sql"}),
    "shell": frozenset({".sh", ".bash", ".zsh", ".ps1"}),
    "html": frozenset({".html", ".htm", ".xhtml", ".ejs", ".hbs", ".handlebars",
                        ".jinja", ".jinja2", ".njk", ".pug"}),
    "css": frozenset({".css", ".scss", ".sass", ".less"}),
    "yaml": frozenset({".yaml", ".yml"}),
    "xml": frozenset({".xml", ".xsl", ".xslt", ".xsd", ".pom", ".wsdl"}),
    "scala": frozenset({".scala", ".sc", ".sbt"}),
    "groovy": frozenset({".groovy", ".gvy", ".gy", ".gsh", ".gradle"}),
    "dockerfile": frozenset({".dockerfile"}),
    "terraform": frozenset({".tf", ".tfvars", ".hcl"}),
}

# Extensions that should NEVER have code-analysis rules run on them
NON_SOURCE_EXTENSIONS: FrozenSet[str] = frozenset({
    ".json", ".lock", ".min.js", ".min.css", ".map",
    ".d.ts", ".snap", ".wasm",
})


# ─── Framework → Rule Prefix/Tag Mapping ─────────────────────────────
# Maps framework names to rule_id patterns that should ONLY fire
# when that framework is detected.

FRAMEWORK_RULE_PATTERNS: Dict[str, Tuple[str, ...]] = {
    "nextjs": (
        "nextjs", "next-", "next_", "NEXT-", "NEXT_",
    ),
    "express": (
        "express", "EXPRESS",
    ),
    "react": (
        "react", "REACT",
    ),
    "angular": (
        "angular", "ANGULAR",
    ),
    "vue": (
        "vue", "VUE",
    ),
    "flask": (
        "flask", "FLASK",
    ),
    "django": (
        "django", "DJANGO",
    ),
    "fastapi": (
        "fastapi", "FASTAPI",
    ),
    "spring": (
        "spring", "SPRING",
    ),
    "rails": (
        "rails", "RAILS",
    ),
    "laravel": (
        "laravel", "LARAVEL",
    ),
    "symfony": (
        "symfony", "SYMFONY",
    ),
}


def get_file_extension(file_path: str) -> str:
    """Extract normalized lowercase extension from file path."""
    _, ext = os.path.splitext(file_path.lower())
    return ext


def is_valid_file_for_language(file_path: str, rule_language: str) -> bool:
    """PART 6: Check if a file's extension matches the rule's target language.

    Rules must only run on supported file types:
    - Python rules → only .py files
    - JavaScript rules → .js/.ts files
    - HTML rules → .html files
    - Never run language rules on JSON or lock files

    Args:
        file_path: Path to the file being scanned.
        rule_language: The language the rule targets.

    Returns:
        True if the file extension matches the rule's language.
    """
    lang_lower = rule_language.lower()

    # Universal/all rules can run on any source file
    if lang_lower in ("all", "universal"):
        ext = get_file_extension(file_path)
        # But never on non-source files
        return ext not in NON_SOURCE_EXTENSIONS

    # Get valid extensions for this language
    valid_extensions = LANGUAGE_EXTENSIONS.get(lang_lower)
    if valid_extensions is None:
        # Unknown language — allow (don't block)
        return True

    ext = get_file_extension(file_path)
    return ext in valid_extensions


def get_rule_framework(rule_id: str) -> Optional[str]:
    """Extract framework name from a rule ID, if applicable.

    Returns the framework name or None if the rule is framework-agnostic.
    """
    rule_id_lower = rule_id.lower()
    for framework, patterns in FRAMEWORK_RULE_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in rule_id_lower:
                return framework
    return None


def should_rule_execute(
    rule_id: str,
    rule_language: str,
    file_path: str,
    detected_frameworks: FrozenSet[str],
) -> Tuple[bool, str]:
    """PART 2: Determine if a rule should execute given the project context.

    Checks:
    1. File type filtering (PART 6) — rule language must match file extension
    2. Framework gating (PART 2) — framework rules only run if framework detected

    Args:
        rule_id: The rule's unique identifier.
        rule_language: The language the rule targets.
        file_path: Path to the file being scanned.
        detected_frameworks: Set of frameworks detected in the project.

    Returns:
        (should_execute, reason) — False with reason if rule should be skipped.
    """
    # Check file type filtering
    if not is_valid_file_for_language(file_path, rule_language):
        return False, f"file_type_mismatch:{rule_language}"

    # Check framework gating
    rule_framework = get_rule_framework(rule_id)
    if rule_framework and rule_framework not in detected_frameworks:
        return False, f"framework_missing:{rule_framework}"

    return True, ""


def filter_rules_for_file(
    rules: list,
    file_path: str,
    file_language: str,
    detected_frameworks: FrozenSet[str],
) -> Tuple[list, int]:
    """Filter a list of compiled rules to only those applicable to a file.

    Combines file type filtering and framework context gating.

    Args:
        rules: List of CompiledRule objects.
        file_path: Path to the file being scanned.
        file_language: The detected language of the file.
        detected_frameworks: Set of detected project frameworks.

    Returns:
        (filtered_rules, skipped_count)
    """
    filtered = []
    skipped = 0

    for compiled_rule in rules:
        rule = compiled_rule.rule
        should_run, reason = should_rule_execute(
            rule.rule_id,
            rule.language,
            file_path,
            detected_frameworks,
        )
        if not should_run:
            skipped += 1
            continue
        filtered.append(compiled_rule)

    return filtered, skipped


# ─── Web-Specific CWE Auto-Gating ───────────────────────────────────
# CWEs that are inherently web-only — if no web framework context is
# detected in the file, confidence is penalized.

WEB_ONLY_CWES: FrozenSet[str] = frozenset({
    "CWE-79",   # XSS
    "CWE-352",  # CSRF
    "CWE-918",  # SSRF
    "CWE-601",  # Open Redirect
})

# Import patterns that indicate web framework usage
WEB_FRAMEWORK_IMPORTS = (
    # Python
    "from flask", "import flask", "from fastapi", "import fastapi",
    "from django", "import django", "from starlette", "from sanic",
    "from aiohttp", "from tornado", "from bottle",
    # JavaScript/TypeScript
    "require('express')", 'require("express")', "from 'express'",
    "from 'koa'", "from 'hapi'", "from 'fastify'", "from 'next",
    "require('http')", 'require("http")',
    # Java
    "import org.springframework", "@RestController", "@Controller",
    "import javax.servlet", "import jakarta.servlet",
    # Go
    '"net/http"', '"github.com/gin-gonic', '"github.com/labstack/echo',
    '"github.com/gorilla/mux',
    # PHP
    "use Illuminate", "Route::", "use Symfony",
    # Ruby
    "Rails.application", "class ApplicationController", "Sinatra",
    # Route decorators
    "@app.route", "@router.", "@api_view", "app.get(", "app.post(",
    "router.get(", "router.post(",
)


def file_has_web_context(content_lower: str) -> bool:
    """Check if file content has web framework imports or route decorators."""
    for sig in WEB_FRAMEWORK_IMPORTS:
        if sig.lower() in content_lower:
            return True
    return False


def get_web_gating_penalty(
    cwe: str,
    file_content_lower: str,
) -> float:
    """Return confidence penalty for web-only CWE in non-web file.

    Returns 0.0 if no penalty applies, or a positive penalty value.
    """
    if not cwe:
        return 0.0

    # Normalize CWE format
    cwe_upper = cwe.upper().strip()
    if not cwe_upper.startswith("CWE-"):
        cwe_upper = f"CWE-{cwe_upper}"

    if cwe_upper not in WEB_ONLY_CWES:
        return 0.0

    if file_has_web_context(file_content_lower):
        return 0.0

    # No web context → penalize
    return 35.0

