"""
False Positive Reduction Engine — contextual validation layer.

Runs AFTER logic detectors and dataflow analysis, BEFORE clustering.
Applies four independent techniques to suppress or penalize findings
that are likely false positives, improving precision without sacrificing
recall.

Pipeline position:
    Detection → Rule Intelligence → Logic Detectors → Dataflow Analysis
    → **False Positive Control** → Clustering → Exploit Chain → Severity Norm

Techniques:
    1. Framework Context Validation — framework-specific rules only fire
       when framework imports/requires are detected in the file.
    2. Sanitization Detection — confidence reduced when known sanitizers
       appear near the finding line.
    3. Test File Suppression — severity downgraded for findings inside
       test files/directories.
    4. Safe Pattern Detection — suppresses rules when safe constructs
       (ORM, parameterized queries, prepared statements) are present.

Constraints:
    - Deterministic: NO AI, NO randomness, NO external calls
    - Performance: O(n × m) where n = findings, m = avg file lines
    - No AST parsing — text-based heuristics only
    - Thread-safe: operates on mutable EngineFinding objects in main process
"""

import logging
import os
import re
from collections import defaultdict
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from engine.models import EngineFinding

logger = logging.getLogger("engine.false_positive_control")

# ═══════════════════════════════════════════════════════════════════════
# 1. FRAMEWORK CONTEXT VALIDATION
# ═══════════════════════════════════════════════════════════════════════

# Map from framework identifier (found in rule_id or tags) to required
# import signatures.  If a rule matches a framework key but none of the
# signatures appear in the file, confidence is penalized.

FRAMEWORK_SIGNATURES: Dict[str, Tuple[str, ...]] = {
    # Python frameworks
    "flask": (
        "import flask",
        "from flask",
    ),
    "django": (
        "import django",
        "from django",
        "django.conf",
    ),
    "fastapi": (
        "import fastapi",
        "from fastapi",
    ),
    # Java / JVM frameworks
    "spring": (
        "org.springframework",
        "import org.springframework",
        "spring-boot",
        "@SpringBootApplication",
        "@RestController",
    ),
    "struts": (
        "org.apache.struts",
        "import org.apache.struts",
    ),
    # JavaScript / Node.js frameworks
    "express": (
        "require(\"express\")",
        "require('express')",
        "from \"express\"",
        "from 'express'",
        "import express",
    ),
    "nextjs": (
        "next/",
        "from \"next",
        "from 'next",
        "require(\"next",
        "require('next",
        "@next/",
    ),
    "react": (
        "import React",
        "from \"react\"",
        "from 'react'",
        "require(\"react\")",
        "require('react')",
    ),
    # PHP frameworks
    "laravel": (
        "use Illuminate",
        "namespace App\\",
        "use App\\",
        "Laravel",
    ),
    "symfony": (
        "use Symfony",
        "Symfony\\",
    ),
    # Ruby frameworks
    "rails": (
        "require 'rails'",
        "require \"rails\"",
        "Rails.application",
        "ActionController",
        "ActiveRecord",
        "class ApplicationController",
    ),
    # Scala
    "play": (
        "import play.",
        "play.api",
    ),
    "akka": (
        "import akka.",
        "akka.actor",
    ),
}

# Confidence penalty when framework not detected (percentage points)
FRAMEWORK_MISSING_PENALTY = 40.0

# Pre-compile lowercase signature sets for fast lookup
_FRAMEWORK_SIGS_LOWER: Dict[str, Tuple[str, ...]] = {
    fw: tuple(sig.lower() for sig in sigs)
    for fw, sigs in FRAMEWORK_SIGNATURES.items()
}


def _detect_framework_from_rule(finding: EngineFinding) -> Optional[str]:
    """Extract framework identifier from a finding's rule metadata.

    Checks rule_id prefix, category, and intelligence_modifiers for
    known framework names.  Returns lowercase framework key or None.
    """
    rule_id_lower = finding.rule_id.lower()
    category_lower = finding.category.lower() if finding.category else ""

    # Check rule_id for framework prefix patterns (e.g. EXTREME-SPRING-001, FW-LARAVEL-002)
    for fw_key in FRAMEWORK_SIGNATURES:
        if fw_key in rule_id_lower:
            return fw_key

    # Check exploit_chain_name and intelligence_modifiers
    chain = getattr(finding, "exploit_chain_name", "")
    if chain:
        chain_lower = chain.lower()
        for fw_key in FRAMEWORK_SIGNATURES:
            if fw_key in chain_lower:
                return fw_key

    return None


def _file_has_framework_imports(
    content_lower: str, framework: str
) -> bool:
    """Check if file content contains any import signature for the given framework."""
    sigs = _FRAMEWORK_SIGS_LOWER.get(framework, ())
    for sig in sigs:
        if sig in content_lower:
            return True
    return False


def _apply_framework_validation(
    findings: List[EngineFinding],
    file_contents: Dict[str, str],
) -> int:
    """Apply framework context validation to all findings.

    Returns count of findings penalized.
    """
    # Cache: file_name -> {framework -> bool}
    framework_cache: Dict[str, Dict[str, bool]] = {}
    penalized = 0

    for finding in findings:
        fw = _detect_framework_from_rule(finding)
        if not fw:
            continue

        fname = finding.file_name
        content = file_contents.get(fname, "")
        if not content:
            continue

        # Check cache
        if fname not in framework_cache:
            framework_cache[fname] = {}
        if fw not in framework_cache[fname]:
            framework_cache[fname][fw] = _file_has_framework_imports(
                content.lower(), fw
            )

        if not framework_cache[fname][fw]:
            # Framework not detected in file — penalize confidence
            base = finding.adjusted_confidence or finding.confidence
            penalty = FRAMEWORK_MISSING_PENALTY
            new_conf = max(5.0, base - penalty)
            finding.adjusted_confidence = new_conf
            if "fp_framework_missing" not in finding.intelligence_modifiers:
                finding.intelligence_modifiers.append("fp_framework_missing")
            penalized += 1

    return penalized


# ═══════════════════════════════════════════════════════════════════════
# 2. SANITIZATION DETECTION
# ═══════════════════════════════════════════════════════════════════════

# Map: language → list of sanitization patterns (compiled regex)
# These detect common sanitization/escaping functions that neutralize
# user input before it reaches a sink.

_SANITIZER_PATTERNS_RAW: Dict[str, List[str]] = {
    "python": [
        r"html\.escape\s*\(",
        r"bleach\.clean\s*\(",
        r"markupsafe\.escape\s*\(",
        r"escape\s*\(",
        r"cgi\.escape\s*\(",
        r"django\.utils\.html\.escape\s*\(",
        r"sanitize\w*\s*\(",
        r"clean_html\s*\(",
    ],
    "java": [
        r"StringEscapeUtils\.\w+\s*\(",
        r"ESAPI\.\w*encoder\s*\(\)",
        r"HtmlUtils\.htmlEscape\s*\(",
        r"Jsoup\.clean\s*\(",
        r"OWASP\.encoder",
        r"sanitize\w*\s*\(",
        r"PreparedStatement",
    ],
    "javascript": [
        r"DOMPurify\.sanitize\s*\(",
        r"validator\.escape\s*\(",
        r"xss\s*\(\s*",
        r"sanitize\w*\s*\(",
        r"escapeHtml\s*\(",
        r"createTextNode\s*\(",
        r"encodeURIComponent\s*\(",
    ],
    "typescript": [
        r"DOMPurify\.sanitize\s*\(",
        r"validator\.escape\s*\(",
        r"sanitize\w*\s*\(",
        r"escapeHtml\s*\(",
        r"encodeURIComponent\s*\(",
    ],
    "csharp": [
        r"HttpUtility\.HtmlEncode\s*\(",
        r"AntiXssEncoder\.\w+\s*\(",
        r"WebUtility\.HtmlEncode\s*\(",
        r"Sanitize\w*\s*\(",
        r"SqlParameter\s*\(",
    ],
    "php": [
        r"htmlspecialchars\s*\(",
        r"htmlentities\s*\(",
        r"strip_tags\s*\(",
        r"filter_var\s*\(",
        r"mysqli_real_escape_string\s*\(",
        r"PDO::prepare\s*\(",
        r"addslashes\s*\(",
    ],
    "ruby": [
        r"\.html_safe\b",
        r"ERB::Util\.html_escape\s*\(",
        r"sanitize\s*\(",
        r"Rack::Utils\.escape_html\s*\(",
        r"CGI\.escapeHTML\s*\(",
    ],
    "go": [
        r"html\.EscapeString\s*\(",
        r"template\.HTMLEscapeString\s*\(",
        r"url\.QueryEscape\s*\(",
        r"bluemonday\.\w+\(",
    ],
    "kotlin": [
        r"StringEscapeUtils\.\w+\s*\(",
        r"HtmlUtils\.htmlEscape\s*\(",
        r"sanitize\w*\s*\(",
    ],
    "swift": [
        r"\.addingPercentEncoding\b",
        r"sanitize\w*\s*\(",
        r"CFURLCreateStringByAddingPercentEscapes\b",
    ],
    "rust": [
        r"html_escape\s*\(",
        r"encode_safe\s*\(",
        r"sanitize\w*\s*\(",
        r"escape_default\s*\(",
    ],
}

# Compiled sanitizer patterns (built lazily)
_SANITIZER_COMPILED: Dict[str, List[re.Pattern]] = {}

# Confidence penalty when sanitization detected (percentage points)
SANITIZATION_PENALTY = 50.0

# Sanitization proximity: finding must be within this many lines of sanitizer
SANITIZATION_PROXIMITY_LINES = 15


def _get_sanitizer_patterns(language: str) -> List[re.Pattern]:
    """Get compiled sanitizer patterns for a language (lazy compilation)."""
    lang = language.lower()
    if lang not in _SANITIZER_COMPILED:
        raw = _SANITIZER_PATTERNS_RAW.get(lang, [])
        compiled = []
        for pat in raw:
            try:
                compiled.append(re.compile(pat, re.IGNORECASE))
            except re.error:
                logger.warning("Failed to compile sanitizer pattern: %s", pat)
        _SANITIZER_COMPILED[lang] = compiled
    return _SANITIZER_COMPILED[lang]


def _detect_language_from_file(file_name: str) -> str:
    """Infer language from file extension for sanitizer lookup."""
    ext_map = {
        ".py": "python",
        ".java": "java",
        ".kt": "kotlin",
        ".kts": "kotlin",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".cs": "csharp",
        ".php": "php",
        ".rb": "ruby",
        ".go": "go",
        ".swift": "swift",
        ".rs": "rust",
    }
    _, ext = os.path.splitext(file_name.lower())
    return ext_map.get(ext, "")


def _apply_sanitization_detection(
    findings: List[EngineFinding],
    file_contents: Dict[str, str],
) -> int:
    """Detect sanitization near findings and reduce confidence.

    For each finding, checks if any sanitization function appears within
    SANITIZATION_PROXIMITY_LINES of the finding's line number.

    Returns count of findings penalized.
    """
    # Pre-split file contents into lines for proximity checking
    file_lines_cache: Dict[str, List[str]] = {}
    penalized = 0

    for finding in findings:
        fname = finding.file_name
        content = file_contents.get(fname, "")
        if not content:
            continue

        lang = _detect_language_from_file(fname)
        patterns = _get_sanitizer_patterns(lang)
        if not patterns:
            continue

        # Cache line splitting
        if fname not in file_lines_cache:
            file_lines_cache[fname] = content.splitlines()

        lines = file_lines_cache[fname]
        finding_line = finding.line  # 1-based

        # Check proximity window for sanitization calls
        start = max(0, finding_line - SANITIZATION_PROXIMITY_LINES - 1)
        end = min(len(lines), finding_line + SANITIZATION_PROXIMITY_LINES)

        sanitizer_found = False
        for i in range(start, end):
            line_text = lines[i]
            for pat in patterns:
                if pat.search(line_text):
                    sanitizer_found = True
                    break
            if sanitizer_found:
                break

        if sanitizer_found:
            base = finding.adjusted_confidence or finding.confidence
            new_conf = max(5.0, base - SANITIZATION_PENALTY)
            finding.adjusted_confidence = new_conf
            if "fp_sanitization_nearby" not in finding.intelligence_modifiers:
                finding.intelligence_modifiers.append("fp_sanitization_nearby")
            penalized += 1

    return penalized


# ═══════════════════════════════════════════════════════════════════════
# 3. TEST FILE SUPPRESSION
# ═══════════════════════════════════════════════════════════════════════

# Test directory / file name indicators
_TEST_PATH_PATTERNS: Tuple[str, ...] = (
    "/tests/",
    "/test/",
    "/__tests__/",
    "/spec/",
    "/specs/",
    "/testing/",
    "/test_",
    "\\tests\\",
    "\\test\\",
    "\\__tests__\\",
    "\\spec\\",
    "\\specs\\",
    "\\testing\\",
    "\\test_",
)

_TEST_FILE_SUFFIXES: Tuple[str, ...] = (
    "_test.py",
    "_test.go",
    "_test.rb",
    "_test.rs",
    "_spec.rb",
    "_spec.js",
    "_spec.ts",
    ".test.js",
    ".test.ts",
    ".test.tsx",
    ".test.jsx",
    ".spec.js",
    ".spec.ts",
    ".spec.tsx",
    ".spec.jsx",
    "test.java",
    "tests.py",
)

_TEST_FILE_PREFIXES: Tuple[str, ...] = (
    "test_",
    "spec_",
)

# Severity mapping for test findings (downgrade by one level)
_SEVERITY_DOWNGRADE = {
    "Critical": "High",
    "High": "Medium",
    "Medium": "Low",
    "Low": "Low",
}

# Confidence penalty for test files (percentage points)
TEST_FILE_CONFIDENCE_PENALTY = 30.0


def _is_test_file(file_name: str) -> bool:
    """Determine if a file path indicates a test file."""
    path_lower = file_name.lower()
    basename = os.path.basename(path_lower)

    # Check path patterns
    for pattern in _TEST_PATH_PATTERNS:
        if pattern in path_lower:
            return True

    # Check file suffixes
    for suffix in _TEST_FILE_SUFFIXES:
        if basename.endswith(suffix):
            return True

    # Check file prefixes
    for prefix in _TEST_FILE_PREFIXES:
        if basename.startswith(prefix):
            return True

    return False


def _apply_test_file_suppression(findings: List[EngineFinding]) -> int:
    """Downgrade severity and reduce confidence for findings in test files.

    Returns count of findings suppressed.
    """
    suppressed = 0

    for finding in findings:
        if _is_test_file(finding.file_name):
            # Downgrade severity
            new_severity = _SEVERITY_DOWNGRADE.get(finding.severity, finding.severity)
            if new_severity != finding.severity:
                finding.severity = new_severity

            # Reduce confidence
            base = finding.adjusted_confidence or finding.confidence
            new_conf = max(5.0, base - TEST_FILE_CONFIDENCE_PENALTY)
            finding.adjusted_confidence = new_conf

            if "fp_test_file" not in finding.intelligence_modifiers:
                finding.intelligence_modifiers.append("fp_test_file")

            suppressed += 1

    return suppressed


# ═══════════════════════════════════════════════════════════════════════
# 4. SAFE PATTERN DETECTION
# ═══════════════════════════════════════════════════════════════════════

# Patterns that indicate safe constructs — when found near a finding,
# the finding should be suppressed (confidence reduced to near-zero).

# Category → list of safe-pattern regexes
_SAFE_PATTERNS_RAW: Dict[str, List[str]] = {
    # SQL injection: parameterized queries / prepared statements / ORM
    "sql_injection": [
        r"\?\s*,",                                 # Positional placeholders
        r"%s\s*,",                                 # Python DB-API placeholders
        r":\w+\s*",                                # Named parameters :param
        r"@\w+\s*",                                # MSSQL @param
        r"\$\d+",                                  # PostgreSQL $1, $2
        r"\.where\s*\(",                           # ORM where()
        r"\.filter\s*\(",                          # ORM filter()
        r"\.filter_by\s*\(",                       # SQLAlchemy filter_by()
        r"\.query\s*\.\s*\w+\s*\(",               # ORM chained query
        r"PreparedStatement\b",                    # Java PreparedStatement
        r"\.prepare\s*\(",                         # PDO/mysql2 prepare()
        r"\.parameterize\b",                       # Rails parameterize
        r"cursor\.execute\s*\(\s*['\"].*%s",       # Python parameterized
        r"\bnamed_params\b",                       # Named param binding
        r"\.createQueryBuilder\s*\(",              # TypeORM/Doctrine QBs
        r"\.createNativeQuery\s*\(",               # JPA native query (parameterized)
        r"sqlx::query\s*!?\s*\(",                  # Rust sqlx
    ],
    # Command injection: safe APIs
    "command_injection": [
        r"subprocess\.run\s*\(\s*\[",              # Python list-form (no shell)
        r"ProcessBuilder\s*\(",                    # Java ProcessBuilder
        r"execFile\s*\(",                          # Node.js execFile (no shell)
        r"spawn\s*\(",                             # Node.js spawn
        r"shlex\.quote\s*\(",                      # Python shlex escaping
        r"shellescape\b",                          # Ruby shellescape
        r"escapeshellarg\s*\(",                    # PHP escapeshellarg
        r"escapeshellcmd\s*\(",                    # PHP escapeshellcmd
        r"Command::new\s*\(",                      # Rust std::process
    ],
    # XSS: output encoding / template auto-escape
    "xss": [
        r"DOMPurify\.sanitize\s*\(",
        r"createTextNode\s*\(",
        r"textContent\s*=",
        r"innerText\s*=",
        r"encodeURIComponent\s*\(",
        r"\{\{.*\}\}",                             # Template auto-escaping (Handlebars, Vue, etc.)
        r"\{%\s*autoescape",                       # Jinja2 autoescape
        r"html\.escape\s*\(",
        r"React\.createElement\s*\(",              # React auto-escapes by default
    ],
    # Path traversal: safe path handling
    "path_traversal": [
        r"os\.path\.basename\s*\(",                # Python basename
        r"os\.path\.abspath\s*\(",                 # Python abspath (canonicalization)
        r"Path\.\w+\s*\(",                         # pathlib
        r"path\.resolve\s*\(",                     # Node.js path.resolve
        r"path\.normalize\s*\(",                   # Node.js normalize
        r"Paths\.get\s*\(",                        # Java Paths.get (validated)
        r"realpath\s*\(",                          # PHP/C realpath
        r"filepath\.Clean\s*\(",                   # Go filepath.Clean
    ],
    # Deserialization: safe alternatives
    "deserialization": [
        r"json\.loads?\s*\(",                      # JSON is safe (no code exec)
        r"JSON\.parse\s*\(",                       # JSON.parse is safe
        r"json_decode\s*\(",                       # PHP json_decode
        r"Gson\(\)",                               # Java Gson (safe)
        r"ObjectMapper\.\w*read",                  # Jackson (type-restricted)
        r"serde_json::from",                       # Rust serde_json
    ],
}

# Compiled safe patterns (lazy)
_SAFE_COMPILED: Dict[str, List[re.Pattern]] = {}

# Safe pattern proximity (lines)
SAFE_PATTERN_PROXIMITY_LINES = 10

# Confidence penalty when safe pattern detected
SAFE_PATTERN_PENALTY = 60.0


def _get_safe_patterns(category: str) -> List[re.Pattern]:
    """Get compiled safe patterns for a vulnerability category."""
    cat_key = category.lower().replace(" ", "_").replace("-", "_")
    if cat_key not in _SAFE_COMPILED:
        # Try direct match and partial match
        raw = _SAFE_PATTERNS_RAW.get(cat_key, [])
        if not raw:
            for key in _SAFE_PATTERNS_RAW:
                if key in cat_key or cat_key in key:
                    raw = _SAFE_PATTERNS_RAW[key]
                    break
        compiled = []
        for pat in raw:
            try:
                compiled.append(re.compile(pat, re.IGNORECASE))
            except re.error:
                logger.warning("Failed to compile safe pattern: %s", pat)
        _SAFE_COMPILED[cat_key] = compiled
    return _SAFE_COMPILED[cat_key]


def _map_rule_to_safe_category(finding: EngineFinding) -> Optional[str]:
    """Map a finding to a safe-pattern category for lookup.

    Uses CWE, rule_id prefix, and vulnerability_type to determine
    which safe-pattern set applies.
    """
    cwe = finding.cwe.lower() if finding.cwe else ""
    rule_id = finding.rule_id.lower()
    vuln_type = (finding.vulnerability_type or "").lower()
    category = (finding.category or "").lower()

    # SQL injection
    if any(x in cwe for x in ("cwe-89", "sql")):
        return "sql_injection"
    if any(x in rule_id for x in ("sqli", "sql-inj", "sql_inj")):
        return "sql_injection"
    if "sql" in vuln_type and "inject" in vuln_type:
        return "sql_injection"

    # Command injection / RCE
    if any(x in cwe for x in ("cwe-78", "cwe-77")):
        return "command_injection"
    if any(x in rule_id for x in ("rce", "cmd-inj", "cmd_inj", "shell-inj", "shell_inj")):
        return "command_injection"
    if "command" in vuln_type and "inject" in vuln_type:
        return "command_injection"

    # XSS
    if "cwe-79" in cwe:
        return "xss"
    if "xss" in rule_id or "xss" in category:
        return "xss"
    if "cross" in vuln_type and "script" in vuln_type:
        return "xss"

    # Path traversal
    if "cwe-22" in cwe:
        return "path_traversal"
    if any(x in rule_id for x in ("pt-", "path-trav", "path_trav")):
        return "path_traversal"

    # Deserialization
    if "cwe-502" in cwe:
        return "deserialization"
    if "deser" in rule_id or "deser" in vuln_type:
        return "deserialization"

    return None


def _apply_safe_pattern_detection(
    findings: List[EngineFinding],
    file_contents: Dict[str, str],
) -> int:
    """Detect safe patterns near findings and suppress them.

    Returns count of findings suppressed.
    """
    file_lines_cache: Dict[str, List[str]] = {}
    suppressed = 0

    for finding in findings:
        safe_cat = _map_rule_to_safe_category(finding)
        if not safe_cat:
            continue

        patterns = _get_safe_patterns(safe_cat)
        if not patterns:
            continue

        fname = finding.file_name
        content = file_contents.get(fname, "")
        if not content:
            continue

        # Cache line splitting
        if fname not in file_lines_cache:
            file_lines_cache[fname] = content.splitlines()

        lines = file_lines_cache[fname]
        finding_line = finding.line  # 1-based

        # Check proximity window for safe patterns
        start = max(0, finding_line - SAFE_PATTERN_PROXIMITY_LINES - 1)
        end = min(len(lines), finding_line + SAFE_PATTERN_PROXIMITY_LINES)

        safe_found = False
        for i in range(start, end):
            line_text = lines[i]
            for pat in patterns:
                if pat.search(line_text):
                    safe_found = True
                    break
            if safe_found:
                break

        if safe_found:
            base = finding.adjusted_confidence or finding.confidence
            new_conf = max(5.0, base - SAFE_PATTERN_PENALTY)
            finding.adjusted_confidence = new_conf
            if "fp_safe_pattern" not in finding.intelligence_modifiers:
                finding.intelligence_modifiers.append("fp_safe_pattern")
            suppressed += 1

    return suppressed


# ═══════════════════════════════════════════════════════════════════════
# 5. COMMENT / DEAD CODE DETECTION
# ═══════════════════════════════════════════════════════════════════════

# Additional FP reducer: detect findings on commented-out lines
_COMMENT_PREFIXES: Dict[str, Tuple[str, ...]] = {
    "python": ("#",),
    "ruby": ("#",),
    "php": ("//", "#", "/*"),
    "java": ("//", "/*", "*"),
    "javascript": ("//", "/*", "*"),
    "typescript": ("//", "/*", "*"),
    "csharp": ("//", "/*", "*"),
    "go": ("//", "/*"),
    "kotlin": ("//", "/*", "*"),
    "swift": ("//", "/*", "*"),
    "rust": ("//", "/*", "*"),
    "c": ("//", "/*", "*"),
    "cpp": ("//", "/*", "*"),
    "scala": ("//", "/*", "*"),
}

COMMENT_PENALTY = 70.0


def _apply_comment_detection(
    findings: List[EngineFinding],
    file_contents: Dict[str, str],
) -> int:
    """Detect findings on commented-out lines and penalize them.

    Returns count of findings penalized.
    """
    file_lines_cache: Dict[str, List[str]] = {}
    penalized = 0

    for finding in findings:
        fname = finding.file_name
        content = file_contents.get(fname, "")
        if not content:
            continue

        lang = _detect_language_from_file(fname)
        prefixes = _COMMENT_PREFIXES.get(lang, ())
        if not prefixes:
            continue

        if fname not in file_lines_cache:
            file_lines_cache[fname] = content.splitlines()

        lines = file_lines_cache[fname]
        line_idx = finding.line - 1  # convert to 0-based

        if 0 <= line_idx < len(lines):
            stripped = lines[line_idx].lstrip()
            is_comment = any(stripped.startswith(p) for p in prefixes)

            if is_comment:
                base = finding.adjusted_confidence or finding.confidence
                new_conf = max(5.0, base - COMMENT_PENALTY)
                finding.adjusted_confidence = new_conf
                if "fp_commented_code" not in finding.intelligence_modifiers:
                    finding.intelligence_modifiers.append("fp_commented_code")
                penalized += 1

    return penalized


# ═══════════════════════════════════════════════════════════════════════
# 6. WEB-CWE CONTEXT GATING
# ═══════════════════════════════════════════════════════════════════════

WEB_CWE_PENALTY = 35.0


def _apply_web_cwe_gating(
    findings: List[EngineFinding],
    file_contents: Dict[str, str],
) -> int:
    """Penalize web-only CWEs (XSS, CSRF, SSRF) in files without web context.

    Returns count of findings penalized.
    """
    from engine.context_gating import get_web_gating_penalty

    # Cache: file_name → content_lower
    content_cache: Dict[str, str] = {}
    penalized = 0

    for finding in findings:
        if not finding.cwe:
            continue

        fname = finding.file_name
        if fname not in content_cache:
            raw = file_contents.get(fname, "")
            content_cache[fname] = raw.lower() if raw else ""

        penalty = get_web_gating_penalty(finding.cwe, content_cache[fname])
        if penalty > 0:
            base = finding.adjusted_confidence or finding.confidence
            new_conf = max(5.0, base - penalty)
            finding.adjusted_confidence = new_conf
            if "fp_web_cwe_no_context" not in finding.intelligence_modifiers:
                finding.intelligence_modifiers.append("fp_web_cwe_no_context")
            penalized += 1

    return penalized


# ═══════════════════════════════════════════════════════════════════════
# 7. IMPORT-LINE SUPPRESSION
# ═══════════════════════════════════════════════════════════════════════

# Patterns that indicate a line is an import/require/use statement
_IMPORT_PREFIXES: Tuple[str, ...] = (
    "import ",
    "from ",
    "require(",
    "require(",
    "use ",
    "include ",
    "include_once ",
    "require_once ",
    "using ",
    "include(",
    "#include ",
)

IMPORT_LINE_PENALTY = 55.0


def _apply_import_line_suppression(
    findings: List[EngineFinding],
    file_contents: Dict[str, str],
) -> int:
    """Penalize findings on import/require lines — these are declarations,
    not actual vulnerability usage points.

    E.g., `import md5` is not a vulnerability; `hashlib.md5(data)` is.

    Returns count of findings penalized.
    """
    file_lines_cache: Dict[str, List[str]] = {}
    penalized = 0

    for finding in findings:
        fname = finding.file_name
        content = file_contents.get(fname, "")
        if not content:
            continue

        if fname not in file_lines_cache:
            file_lines_cache[fname] = content.splitlines()

        lines = file_lines_cache[fname]
        line_idx = finding.line - 1  # 0-based

        if 0 <= line_idx < len(lines):
            stripped = lines[line_idx].lstrip().lower()
            is_import = any(stripped.startswith(p) for p in _IMPORT_PREFIXES)

            if is_import:
                base = finding.adjusted_confidence or finding.confidence
                new_conf = max(5.0, base - IMPORT_LINE_PENALTY)
                finding.adjusted_confidence = new_conf
                if "fp_import_line" not in finding.intelligence_modifiers:
                    finding.intelligence_modifiers.append("fp_import_line")
                penalized += 1

    return penalized


# ═══════════════════════════════════════════════════════════════════════
# 8. MULTI-LINE COMMENT / DOCSTRING DETECTION
# ═══════════════════════════════════════════════════════════════════════

MULTILINE_COMMENT_PENALTY = 65.0


def _is_inside_multiline_comment(
    lines: List[str], line_idx: int, lang: str,
) -> bool:
    """Check if a line is inside a multi-line comment or docstring.

    Supports:
    - Python: triple-quoted strings (''' or \"\"\")
    - C-family: /* ... */ block comments
    """
    if lang == "python":
        # Count triple-quote boundaries before this line
        in_triple = False
        for i in range(min(line_idx + 1, len(lines))):
            line = lines[i]
            # Count triple-quote occurrences on this line
            count = line.count('"""') + line.count("'''")
            for _ in range(count):
                in_triple = not in_triple
        return in_triple and line_idx < len(lines)

    elif lang in ("java", "javascript", "typescript", "csharp", "go",
                  "kotlin", "swift", "rust", "cpp", "c", "php", "scala"):
        # Track /* ... */ blocks
        in_block = False
        for i in range(min(line_idx + 1, len(lines))):
            line = lines[i]
            if in_block:
                if "*/" in line:
                    in_block = False
            else:
                if "/*" in line:
                    if "*/" not in line or line.index("/*") > line.index("*/"):
                        in_block = True
        return in_block

    return False


def _apply_multiline_comment_detection(
    findings: List[EngineFinding],
    file_contents: Dict[str, str],
) -> int:
    """Detect findings inside multi-line comments/docstrings.

    Returns count of findings penalized.
    """
    file_lines_cache: Dict[str, List[str]] = {}
    penalized = 0

    for finding in findings:
        fname = finding.file_name
        content = file_contents.get(fname, "")
        if not content:
            continue

        lang = _detect_language_from_file(fname)
        if not lang:
            continue

        if fname not in file_lines_cache:
            file_lines_cache[fname] = content.splitlines()

        lines = file_lines_cache[fname]
        line_idx = finding.line - 1  # 0-based

        if _is_inside_multiline_comment(lines, line_idx, lang):
            base = finding.adjusted_confidence or finding.confidence
            new_conf = max(5.0, base - MULTILINE_COMMENT_PENALTY)
            finding.adjusted_confidence = new_conf
            if "fp_multiline_comment" not in finding.intelligence_modifiers:
                finding.intelligence_modifiers.append("fp_multiline_comment")
            penalized += 1

    return penalized


# ═══════════════════════════════════════════════════════════════════════
# PUBLIC ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════


def apply_false_positive_control(
    findings: List[EngineFinding],
    file_contents: Dict[str, str],
) -> List[EngineFinding]:
    """Apply all false positive reduction techniques to findings.

    Called from the main pipeline after dataflow analysis and before
    clustering.  Mutates findings in-place (adjusts confidence, severity,
    intelligence_modifiers).

    Args:
        findings: List of EngineFinding objects from prior pipeline stages.
        file_contents: Dict mapping file_name → full file content string.

    Returns:
        The same list with modified findings (for fluent chaining).
    """
    if not findings:
        return findings

    initial_count = len(findings)

    # 1. Framework context validation
    fw_count = _apply_framework_validation(findings, file_contents)

    # 2. Sanitization detection
    san_count = _apply_sanitization_detection(findings, file_contents)

    # 3. Test file suppression
    test_count = _apply_test_file_suppression(findings)

    # 4. Safe pattern detection
    safe_count = _apply_safe_pattern_detection(findings, file_contents)

    # 5. Comment / dead code detection
    comment_count = _apply_comment_detection(findings, file_contents)

    # 6. Web-CWE context gating (NEW)
    web_count = _apply_web_cwe_gating(findings, file_contents)

    # 7. Import-line suppression (NEW)
    import_count = _apply_import_line_suppression(findings, file_contents)

    # 8. Multi-line comment/docstring detection (NEW)
    mlcomment_count = _apply_multiline_comment_detection(findings, file_contents)

    # Remove findings with confidence below suppression threshold
    SUPPRESSION_THRESHOLD = 10.0
    pre_filter = len(findings)
    findings = [
        f for f in findings
        if (f.adjusted_confidence or f.confidence) >= SUPPRESSION_THRESHOLD
    ]
    filtered = pre_filter - len(findings)

    logger.info(
        "FP control: %d findings processed — "
        "framework=%d, sanitization=%d, test_file=%d, safe_pattern=%d, "
        "comment=%d, web_cwe=%d, import=%d, ml_comment=%d penalized; "
        "%d suppressed (conf < %.0f).",
        initial_count,
        fw_count,
        san_count,
        test_count,
        safe_count,
        comment_count,
        web_count,
        import_count,
        mlcomment_count,
        filtered,
        SUPPRESSION_THRESHOLD,
    )

    return findings


def get_fp_control_stats(findings: List[EngineFinding]) -> Dict[str, int]:
    """Return statistics about FP control actions applied.

    Useful for dashboard / reporting.
    """
    stats = {
        "framework_missing": 0,
        "sanitization_nearby": 0,
        "test_file": 0,
        "safe_pattern": 0,
        "commented_code": 0,
        "total_penalized": 0,
    }

    for f in findings:
        mods = set(f.intelligence_modifiers) if f.intelligence_modifiers else set()
        if "fp_framework_missing" in mods:
            stats["framework_missing"] += 1
        if "fp_sanitization_nearby" in mods:
            stats["sanitization_nearby"] += 1
        if "fp_test_file" in mods:
            stats["test_file"] += 1
        if "fp_safe_pattern" in mods:
            stats["safe_pattern"] += 1
        if "fp_commented_code" in mods:
            stats["commented_code"] += 1

    stats["total_penalized"] = sum(
        1 for f in findings
        if any(m.startswith("fp_") for m in (f.intelligence_modifiers or []))
    )

    return stats
