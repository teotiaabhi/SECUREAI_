"""
Advanced confidence scoring system with input source analysis.

Re-scores each finding based on multiple contextual signals to produce
a final confidence level (high / medium / low). This replaces the
simple numeric confidence with a structured, explainable score.

Pipeline position:
    Pattern Match → Enrichment → **Confidence Rescoring** → Filter → Output

Confidence Levels:
    HIGH   (70-100): Pattern + user-controlled input + sink confirmed
    MEDIUM (40-69):  Pattern + suspicious variable OR partial taint
    LOW    (0-39):   Pattern match only (no context confirmation)

Input Source Classification:
    USER_INPUT:    request params, form data, query strings, headers
    ENVIRONMENT:   os.environ, env vars, config files
    NETWORK:       HTTP responses, API calls, socket data
    INTERNAL:      Constants, literals, hardcoded values
    UNKNOWN:       Cannot determine source
"""

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from engine.models import EngineFinding

logger = logging.getLogger("engine.confidence_scorer")


# ─── Input Source Classification ─────────────────────────────────────

class InputSource(Enum):
    USER_INPUT = "user_input"
    ENVIRONMENT = "environment"
    NETWORK = "network"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


# Patterns that indicate user-controlled input (DANGEROUS)
USER_INPUT_PATTERNS: Tuple[str, ...] = (
    # Python / FastAPI / Flask / Django
    r"request\.\w+(?:\[|\.get\()",
    r"request\.args",
    r"request\.form",
    r"request\.json",
    r"request\.data",
    r"request\.query_params",
    r"request\.path_params",
    r"request\.headers",
    r"request\.cookies",
    r"request\.GET\b",
    r"request\.POST\b",
    r"request\.body",
    r"request\.files",
    r"flask\.request\.",
    r"self\.request\.\w+",
    r"\bparams\[",
    r"sys\.argv",
    r"\binput\s*\(",
    # JavaScript / Express
    r"req\.params\b",
    r"req\.query\b",
    r"req\.body\b",
    r"req\.headers\b",
    r"req\.cookies\b",
    r"req\.path\b",
    r"req\.url\b",
    r"document\.location",
    r"window\.location",
    r"location\.hash",
    r"location\.search",
    r"document\.URL",
    r"\$_GET\b",
    r"\$_POST\b",
    r"\$_REQUEST\b",
    r"\$_COOKIE\b",
    r"\$_FILES\b",
    # Java / Spring
    r"@RequestParam\b",
    r"@PathVariable\b",
    r"@RequestBody\b",
    r"@RequestHeader\b",
    r"HttpServletRequest",
    r"getParameter\s*\(",
    r"getHeader\s*\(",
    r"getCookies\s*\(",
)

# Patterns indicating internal/constant values (SAFE)
INTERNAL_SOURCE_PATTERNS: Tuple[str, ...] = (
    r'https?://(?:api\.)?[\w.-]+\.(?:com|org|net|io)',   # Hardcoded URLs
    r'"https?://',
    r"'https?://",
    r"settings\.\w+",
    r"config\.\w+",
    r"os\.environ\b",
    r"getenv\s*\(",
    r'[A-Z_]{3,}\s*=\s*["\']',  # CONSTANT = "value"
)

# Compiled pattern cache
_USER_INPUT_COMPILED: Optional[List[re.Pattern]] = None
_INTERNAL_COMPILED: Optional[List[re.Pattern]] = None


def _get_user_input_patterns() -> List[re.Pattern]:
    global _USER_INPUT_COMPILED
    if _USER_INPUT_COMPILED is None:
        _USER_INPUT_COMPILED = []
        for pat in USER_INPUT_PATTERNS:
            try:
                _USER_INPUT_COMPILED.append(re.compile(pat, re.IGNORECASE))
            except re.error:
                pass
    return _USER_INPUT_COMPILED


def _get_internal_patterns() -> List[re.Pattern]:
    global _INTERNAL_COMPILED
    if _INTERNAL_COMPILED is None:
        _INTERNAL_COMPILED = []
        for pat in INTERNAL_SOURCE_PATTERNS:
            try:
                _INTERNAL_COMPILED.append(re.compile(pat, re.IGNORECASE))
            except re.error:
                pass
    return _INTERNAL_COMPILED


def classify_input_source(
    code_snippet: str,
    surrounding_context: str = "",
) -> Tuple[InputSource, float]:
    """Classify the likely input source for a code snippet.

    Returns (source_type, confidence_modifier).
    - User input → positive modifier (higher confidence)
    - Internal/constant → negative modifier (lower confidence)
    """
    text = f"{code_snippet}\n{surrounding_context}"

    user_hits = sum(
        1 for p in _get_user_input_patterns() if p.search(text)
    )
    internal_hits = sum(
        1 for p in _get_internal_patterns() if p.search(text)
    )

    if user_hits >= 2:
        return InputSource.USER_INPUT, 15.0
    elif user_hits == 1:
        return InputSource.USER_INPUT, 10.0
    elif internal_hits >= 2:
        return InputSource.INTERNAL, -20.0
    elif internal_hits == 1:
        return InputSource.INTERNAL, -10.0
    else:
        return InputSource.UNKNOWN, 0.0


# ─── Authorization Check Detection ──────────────────────────────────

OWNERSHIP_CHECK_PATTERNS: Tuple[str, ...] = (
    # Python FastAPI / SQLAlchemy ownership filters
    r"\.where\([^)]*user_id\s*==\s*user\.",
    r"\.where\([^)]*user\.id\b",
    r"\.where\([^)]*owner_id\s*==",
    r"\.where\([^)]*tenant_id\s*==",
    r"\.filter_by\s*\([^)]*user_id\s*=",
    r"\.filter_by\s*\([^)]*owner_id\s*=",
    r"\.filter_by\s*\([^)]*tenant_id\s*=",
    r"\.filter\s*\([^)]*\.user_id\s*==",
    # Django ORM
    r"\.objects\.filter\s*\([^)]*user\s*=",
    r"\.objects\.filter\s*\([^)]*owner\s*=",
    r"\.objects\.filter\s*\([^)]*tenant\s*=",
    # Flask / general
    r"if\s+\w*\.user_id\s*!=\s*current_user",
    r"if\s+\w*\.owner_id\s*!=",
    r"if\s+not\s+.*\.is_owner",
    r"require_ownership\s*\(",
    r"check_ownership\s*\(",
    r"verify_ownership\s*\(",
    r"has_permission\s*\(",
    r"can_access\s*\(",
    # Express / Node
    r"req\.user\.id\s*[!=]==",
    r"userId\s*[!=]==",
)

_OWNERSHIP_COMPILED: Optional[List[re.Pattern]] = None


def _get_ownership_patterns() -> List[re.Pattern]:
    global _OWNERSHIP_COMPILED
    if _OWNERSHIP_COMPILED is None:
        _OWNERSHIP_COMPILED = []
        for pat in OWNERSHIP_CHECK_PATTERNS:
            try:
                _OWNERSHIP_COMPILED.append(re.compile(pat, re.IGNORECASE))
            except re.error:
                pass
    return _OWNERSHIP_COMPILED


def detect_authorization_check(
    file_content: str,
    finding_line: int,
    radius: int = 30,
) -> Tuple[bool, float]:
    """Check if authorization/ownership validation exists near the finding.

    Searches ±radius lines around the finding for ownership patterns.

    Returns (has_auth_check, confidence_modifier).
    """
    lines = file_content.split("\n")
    start = max(0, finding_line - 1 - radius)
    end = min(len(lines), finding_line + radius)
    context = "\n".join(lines[start:end])

    auth_hits = sum(
        1 for p in _get_ownership_patterns() if p.search(context)
    )

    if auth_hits >= 2:
        return True, -25.0  # Strong auth check — big confidence reduction
    elif auth_hits == 1:
        return True, -15.0  # Single auth pattern found
    return False, 0.0


# ─── Safe Pattern Detection ──────────────────────────────────────────

# Rule-family-specific safe patterns that suppress false positives
SAFE_PATTERNS: Dict[str, Tuple[str, ...]] = {
    "sql_injection": (
        r"\.execute\s*\([^)]*,\s*[\(\[]",  # Parameterized: execute(query, (param,))
        r"\.execute\s*\([^)]*,\s*\{",       # Named params: execute(query, {"key": val})
        r"\btext\s*\([^)]+\)\.bindparams\b",
        r"\bobjects\.filter\b",
        r"\bobjects\.get\b",
        r"\bobjects\.exclude\b",
        r"prepared_statement",
        r"parameterized",
        r"\?.*,.*\[",                        # Placeholder: "SELECT ? ...", [val]
        r"\$\d+",                            # PostgreSQL positional: $1, $2
    ),
    "xss": (
        r"html\.escape\s*\(",
        r"markupsafe\.escape\s*\(",
        r"bleach\.clean\s*\(",
        r"DOMPurify\.sanitize\s*\(",
        r"Content-Security-Policy",
        r"\.textContent\s*=",
        r"\.innerText\s*=",
        r"auto_escape\s*=\s*True",
    ),
    "ssrf": (
        r"(?:url|endpoint)\s*=\s*[\"'][^\"']*[\"']",  # Hardcoded URL constant
        r"settings\.\w+_URL\b",
        r"config\.\w+_URL\b",
        r"ALLOWED_HOSTS",
        r"allowlist",
        r"whitelist",
        r"validate_url\s*\(",
    ),
    "path_traversal": (
        r"os\.path\.realpath\s*\(",
        r"\.resolve\(\)\.startswith\b",
        r"secure_filename\s*\(",
        r"path\.is_relative_to\s*\(",
        r"os\.path\.abspath\s*\([^)]*\).*startswith",
    ),
    "deserialization": (
        r"yaml\.safe_load\b",
        r"SafeLoader\b",
        r"json\.loads?\b",
        r"jsonpickle.*set_encoder_options.*unpicklable\s*=\s*False",
    ),
    "command_injection": (
        r"subprocess\.run\s*\([^)]*\bshell\s*=\s*False\b",
        r"shlex\.quote\s*\(",
        r"shlex\.split\s*\(",
        r"subprocess\.\w+\s*\(\s*\[",  # List form (no shell)
    ),
    "prototype_pollution": (
        r"Object\.freeze\s*\(",
        r"Object\.seal\s*\(",
        r"JSON\.parse\s*\(",  # JSON.parse is safe for prototype pollution
        r"Math\.\w+\s*\(",   # Math methods with spread are not pollution
        r"\.\.\.\w+",        # Spread operator in safe context
    ),
    "idor": (
        r"user_id\s*==\s*user\.",
        r"\.user_id\s*==\s*\w+\.id\b",
        r"owner_id\s*==",
        r"tenant_id\s*==",
        r"\.where\([^)]*user",
        r"Depends\s*\(\s*get_current_user\s*\)",
        r"@login_required\b",
        r"@requires_auth\b",
    ),
}

_SAFE_COMPILED: Dict[str, List[re.Pattern]] = {}


def _get_safe_patterns(family: str) -> List[re.Pattern]:
    """Get compiled safe patterns for a vulnerability family."""
    if family not in _SAFE_COMPILED:
        raw = SAFE_PATTERNS.get(family, ())
        compiled = []
        for pat in raw:
            try:
                compiled.append(re.compile(pat, re.IGNORECASE))
            except re.error:
                pass
        _SAFE_COMPILED[family] = compiled
    return _SAFE_COMPILED[family]


def _map_rule_to_family(rule_id: str, vuln_family: str) -> str:
    """Map a rule ID or vulnerability family to a safe-pattern key."""
    rid = rule_id.lower()
    vf = vuln_family.lower()

    if "sql" in rid or "sql" in vf or "sqli" in rid:
        return "sql_injection"
    if "xss" in rid or "xss" in vf or "cross_site" in vf:
        return "xss"
    if "ssrf" in rid or "ssrf" in vf:
        return "ssrf"
    if "path" in rid or "traversal" in vf or "pt-" in rid:
        return "path_traversal"
    if "deser" in rid or "pickle" in rid or "yaml" in vf:
        return "deserialization"
    if "rce" in rid or "command" in vf or "cmdi" in rid or "os.system" in vf:
        return "command_injection"
    if "prototype" in rid or "prototype" in vf:
        return "prototype_pollution"
    if "idor" in rid or "idor" in vf:
        return "idor"

    return ""


def detect_safe_patterns(
    file_content: str,
    finding_line: int,
    rule_id: str,
    vuln_family: str,
    radius: int = 15,
) -> Tuple[bool, float, str]:
    """Check for safe patterns near a finding that indicate it's a false positive.

    Returns (is_safe, confidence_modifier, reason).
    """
    family = _map_rule_to_family(rule_id, vuln_family)
    if not family:
        return False, 0.0, ""

    patterns = _get_safe_patterns(family)
    if not patterns:
        return False, 0.0, ""

    lines = file_content.split("\n")
    start = max(0, finding_line - 1 - radius)
    end = min(len(lines), finding_line + radius)
    context = "\n".join(lines[start:end])

    for pat in patterns:
        m = pat.search(context)
        if m:
            return True, -20.0, f"safe_pattern:{family}:{m.group()[:50]}"

    return False, 0.0, ""


# ─── Confidence Level Classification ─────────────────────────────────

class ConfidenceLevel(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


def classify_confidence(score: float) -> ConfidenceLevel:
    """Classify numeric confidence into HIGH/MEDIUM/LOW."""
    if score >= 70:
        return ConfidenceLevel.HIGH
    elif score >= 40:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


# ─── Main Rescoring Function ─────────────────────────────────────────

@dataclass
class ScoringResult:
    """Detailed scoring breakdown for a finding."""
    original_confidence: float
    final_confidence: float
    confidence_level: ConfidenceLevel
    input_source: InputSource
    has_auth_check: bool
    has_safe_pattern: bool
    modifiers: List[str]


def rescore_finding(
    finding: EngineFinding,
    file_content: str,
) -> ScoringResult:
    """Rescore a finding with full contextual analysis.

    Combines:
    1. Input source classification
    2. Authorization check detection
    3. Safe pattern detection
    4. Educational code detection
    5. Test file detection

    Returns detailed ScoringResult.
    """
    modifiers: List[str] = []
    base = finding.adjusted_confidence or finding.confidence
    cumulative = 0.0

    # 1) Input source analysis
    context_lines = file_content.split("\n")
    start = max(0, finding.line - 1 - 10)
    end = min(len(context_lines), finding.line + 10)
    surrounding = "\n".join(context_lines[start:end])

    source, source_mod = classify_input_source(finding.code_snippet, surrounding)
    cumulative += source_mod
    if source_mod != 0:
        modifiers.append(f"input_source:{source.value}:{source_mod:+.0f}")

    # 2) Authorization check (for IDOR, access control rules)
    if any(k in finding.rule_id.lower() for k in ("idor", "mt-", "priv", "auth", "access")):
        has_auth, auth_mod = detect_authorization_check(file_content, finding.line)
        cumulative += auth_mod
        if auth_mod != 0:
            modifiers.append(f"auth_check:{auth_mod:+.0f}")
    else:
        has_auth = False

    # 3) Safe pattern detection
    is_safe, safe_mod, safe_reason = detect_safe_patterns(
        file_content, finding.line,
        finding.rule_id, finding.vulnerability_family,
    )
    cumulative += safe_mod
    if safe_mod != 0:
        modifiers.append(safe_reason)

    # 4) Test file penalty
    from engine.rule_preconditions import _is_test_file, _is_educational_file
    if _is_test_file(finding.file_name):
        cumulative -= 15.0
        modifiers.append("test_file:-15")

    # 5) Educational code penalty
    content_lower = file_content[:2000].lower()
    if _is_educational_file(finding.file_name, content_lower):
        cumulative -= 30.0
        modifiers.append("educational_code:-30")

    final = max(0.0, min(100.0, base + cumulative))
    level = classify_confidence(final)

    return ScoringResult(
        original_confidence=finding.confidence,
        final_confidence=final,
        confidence_level=level,
        input_source=source,
        has_auth_check=has_auth,
        has_safe_pattern=is_safe,
        modifiers=modifiers,
    )


def apply_confidence_rescoring(
    findings: List[EngineFinding],
    file_contents: Dict[str, str],
) -> Dict[str, int]:
    """Apply confidence rescoring to all findings.

    Mutates findings in place (updates adjusted_confidence and intelligence_modifiers).

    Returns stats: {"rescored": N, "downgraded": N, "upgraded": N}
    """
    stats = {"rescored": 0, "downgraded": 0, "upgraded": 0}

    for finding in findings:
        content = file_contents.get(finding.file_name, "")
        if not content:
            continue

        result = rescore_finding(finding, content)
        old_conf = finding.adjusted_confidence or finding.confidence

        finding.adjusted_confidence = result.final_confidence
        finding.intelligence_modifiers.extend(result.modifiers)

        stats["rescored"] += 1
        if result.final_confidence < old_conf:
            stats["downgraded"] += 1
        elif result.final_confidence > old_conf:
            stats["upgraded"] += 1

    logger.info(
        "Confidence rescoring complete: %d rescored, %d downgraded, %d upgraded",
        stats["rescored"], stats["downgraded"], stats["upgraded"],
    )
    return stats
