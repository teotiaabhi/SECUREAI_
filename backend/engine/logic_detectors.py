"""
Advanced Logic Vulnerability Detectors — deterministic heuristic analysis.

Pipeline position: AFTER Rule Intelligence → BEFORE Vulnerability Clustering.

Detects vulnerability classes that cannot be found by regex pattern matching
alone.  Every detector operates by scanning pre-split lines in a single pass,
maintaining O(n) complexity per file.

Detectors:
    1. Async Race Condition        (LOGIC-RACE-001)  — shared mutable state
       across async boundaries
    2. Timing Attack               (LOGIC-TIMING-001) — non-constant-time
       comparisons in security-sensitive contexts
    3. Dependency Confusion /
       Supply Chain Risk           (LOGIC-SUPPLY-001/002/003) — wildcard,
       unpinned-git, confusion-risk dependencies
    4. Dangerous Build Scripts     (LOGIC-SUPPLY-004) — pipe-to-shell,
       eval, child_process.exec in package.json scripts
    5. Framework Context Validation (adjusts existing findings) — suppresses
       framework-specific false positives when framework is absent
    6. Rate-Limit Race Condition   (LOGIC-RACE-002) — non-atomic
       cache get/set patterns

Constraints:
    - Deterministic: NO AI, NO randomness, NO external calls
    - No AST parsing or taint analysis engine
    - No external libraries (stdlib only)
    - O(n) per file, O(n) total
    - Thread-safe: no global mutable state
    - Production-safe: graceful fallback on all edge cases
"""

import hashlib
import logging
import re
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from engine.models import EngineFinding

logger = logging.getLogger("engine.logic_detectors")

# ─── Global Limits ────────────────────────────────────────────────────

_MAX_FINDINGS_PER_DETECTOR_PER_FILE = 10
_MAX_SNIPPET_CHARS = 800

# =====================================================================
#  DETECTOR 1 — Async Race Condition  (LOGIC-RACE-001)
# =====================================================================
#
# Heuristic:
#   1. Locate module-level mutable state (dict, list, set, object assign)
#   2. Find async functions that write to that state
#   3. In the same async function, verify an 'await' appears before a
#      condition/read of the same state variable
#
# Fires when all three conditions co-exist in the same file.
# =====================================================================

# Module-level mutable state patterns (name = {}, [], etc.)
_GLOBAL_MUTABLE_RE = re.compile(
    r"^([A-Za-z_]\w*)\s*[:=]\s*(\{|\[|set\(|dict\(|list\(|defaultdict\(|"
    r"collections\.OrderedDict\(|Counter\()",
)

# Assignment to a dotted or keyed mutable (shared_state.x = …, cache[k] = …)
_STATE_WRITE_RE = re.compile(
    r"(\b[A-Za-z_]\w*(?:\.\w+|\[.+?\]))\s*(?:=|\+=|-=|\|=|\.append\(|"
    r"\.update\(|\.extend\(|\.add\(|\.pop\(|\.remove\(|\.clear\(|"
    r"\.setdefault\(|del\s)",
)

_AWAIT_RE = re.compile(r"\bawait\s")
_ASYNC_DEF_RE = re.compile(r"^\s*async\s+def\s+(\w+)")

# Read / condition patterns on state variable
_STATE_READ_RE = re.compile(
    r"\bif\s+.*\b{var}\b|\bassert\s+.*\b{var}\b|\breturn\s+.*\b{var}\b"
)


def _detect_async_race_conditions(
    file_lines: Dict[str, List[str]],
) -> List[EngineFinding]:
    """Detector 1: shared mutable state across async boundaries."""
    findings: List[EngineFinding] = []

    for fname, lines in file_lines.items():
        # -- Pass 1: find module-level mutable names -----------------
        global_mutables: Dict[str, int] = {}  # name → line_num
        indent_at_top = True
        for idx, raw_line in enumerate(lines):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith(("#", "//", "'''", '"""')):
                continue

            # Module-level = zero indentation (or file-level)
            if raw_line and raw_line[0] not in (" ", "\t"):
                m = _GLOBAL_MUTABLE_RE.match(stripped)
                if m:
                    global_mutables[m.group(1)] = idx + 1

            # Once we hit a class or non-trivial def at col-0, we're
            # past global scope for new var declarations, but we still
            # the names we already found.

        if not global_mutables:
            continue

        # -- Pass 2: scan async functions for state write + await ----
        file_count = 0
        in_async_fn = False
        async_fn_name = ""
        async_fn_start = 0
        async_fn_indent = 0
        saw_await_before_read = False
        wrote_vars: Set[str] = set()
        flagged_lines: Set[int] = set()

        for idx, raw_line in enumerate(lines):
            if file_count >= _MAX_FINDINGS_PER_DETECTOR_PER_FILE:
                break

            stripped = raw_line.strip()

            # Detect async def
            adef = _ASYNC_DEF_RE.match(raw_line)
            if adef:
                # Flush previous async function
                in_async_fn = True
                async_fn_name = adef.group(1)
                async_fn_start = idx
                async_fn_indent = len(raw_line) - len(raw_line.lstrip())
                saw_await_before_read = False
                wrote_vars = set()
                continue

            if not in_async_fn:
                continue

            # Check if we've left the async function (dedent)
            if stripped and not stripped.startswith(("#", "//")) and raw_line[0] != " " and raw_line[0] != "\t":
                # Back at column 0 → left async body (unless it's a decorator)
                if not stripped.startswith("@"):
                    in_async_fn = False
                    continue

            # Within async body:
            line_lower = stripped.lower()

            # Detect writes to global mutable state
            wm = _STATE_WRITE_RE.search(stripped)
            if wm:
                var_root = wm.group(1).split(".")[0].split("[")[0]
                if var_root in global_mutables:
                    wrote_vars.add(var_root)

            # Detect await
            if _AWAIT_RE.search(stripped):
                if wrote_vars:
                    saw_await_before_read = True

            # Detect read / condition after await
            if saw_await_before_read:
                for var in wrote_vars:
                    read_re = re.compile(
                        rf"\bif\b.*\b{re.escape(var)}\b|"
                        rf"\bassert\b.*\b{re.escape(var)}\b|"
                        rf"\breturn\b.*\b{re.escape(var)}\b",
                    )
                    if read_re.search(stripped) and (idx + 1) not in flagged_lines:
                        flagged_lines.add(idx + 1)
                        line_num = idx + 1
                        snip_start = max(0, idx - 3)
                        snip_end = min(len(lines), idx + 4)
                        snippet = "\n".join(lines[snip_start:snip_end])[:_MAX_SNIPPET_CHARS]

                        det_id = hashlib.sha256(
                            f"LOGIC-RACE-001|{fname}|{line_num}".encode()
                        ).hexdigest()[:16]

                        findings.append(EngineFinding(
                            rule_id="LOGIC-RACE-001",
                            rule_title="Async Race Condition — Shared Mutable State",
                            vulnerability_type="Race Condition",
                            severity="high",
                            confidence=70.0,
                            file_name=fname,
                            line=line_num,
                            description=(
                                f"Global mutable '{var}' is written in async function "
                                f"'{async_fn_name}', then read after an await at line "
                                f"{line_num}. Between the write and the read, another "
                                f"coroutine can modify the shared state, causing a "
                                f"time-of-check-to-time-of-use (TOCTOU) race."
                            ),
                            category="Backend Security",
                            owasp="A04:2021 — Insecure Design",
                            cwe="CWE-362",
                            matched_pattern=stripped[:200],
                            code_snippet=snippet,
                            impact=(
                                "Concurrent coroutines can corrupt shared state, "
                                "leading to authentication bypass, data leakage, "
                                "or privilege escalation depending on the state semantics."
                            ),
                            remediation=(
                                "Use asyncio.Lock to serialize access to shared mutable "
                                "state, or redesign to use request-scoped state instead "
                                "of module-level globals."
                            ),
                            requires_ai_validation=False,
                            severity_weight=9,
                            exploitability_score="High",
                            detection_id=det_id,
                            correlation_flags=["async_race_shared_state"],
                            intelligence_modifiers=["logic_async_race"],
                            vulnerability_family="race_condition",
                        ))
                        file_count += 1

    return findings


# =====================================================================
#  DETECTOR 2 — Timing Attack Detection  (LOGIC-TIMING-001)
# =====================================================================
#
# Heuristic:
#   1. File contains authentication / token / password context markers
#   2. String comparison uses == or != (not constant-time compare)
#   3. Comparison target variable name matches sensitive-name patterns
#
# CWE-208: Observable Timing Discrepancy
# =====================================================================

_AUTH_CONTEXT_RE = re.compile(
    r"\b(?:auth|login|verify|validate|check_password|check_token|"
    r"compare_digest|authenticate|verify_password|verify_token|"
    r"totp|otp|hmac|api_key|secret|session_token|csrf)\b",
    re.IGNORECASE,
)

_TIMING_SENSITIVE_VARS = re.compile(
    r"\b(?:password|passwd|pwd|token|secret|api_key|apikey|"
    r"totp|otp|hmac|hash|digest|expected|stored_hash|"
    r"session_id|csrf_token|auth_code|verification_code|"
    r"reset_token|access_token|refresh_token|pin_code|"
    r"signature|mac|nonce)\b",
    re.IGNORECASE,
)

# Direct == / != comparison with a sensitive variable
_TIMING_COMPARE_RE = re.compile(
    r"""
    \bif\s+.*                         # if-statement
    \b(\w+)\s*(?:==|!=)\s*(\w+)       # var == var  or  var != var
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Also catch: `password == expected` standalone comparisons
_BARE_COMPARE_RE = re.compile(
    r"\b(\w+)\s*(?:==|!=)\s*(\w+)",
)

# Safe comparison functions (hmac.compare_digest, secrets.compare_digest, etc.)
_SAFE_COMPARE_RE = re.compile(
    r"compare_digest|constant_time_compare|secure_compare|"
    r"timing_safe_equal|crypto\.timingSafeEqual|"
    r"MessageDigest\.isEqual|consttime_memequal",
    re.IGNORECASE,
)


def _detect_timing_attacks(
    file_lines: Dict[str, List[str]],
) -> List[EngineFinding]:
    """Detector 2: insecure string comparison in auth contexts."""
    findings: List[EngineFinding] = []

    for fname, lines in file_lines.items():
        # Quick reject: does file contain auth context?
        file_text = "\n".join(lines)
        if not _AUTH_CONTEXT_RE.search(file_text):
            continue

        # Quick reject: if file uses constant-time compare throughout
        has_safe_compare = bool(_SAFE_COMPARE_RE.search(file_text))

        file_count = 0
        for idx, raw_line in enumerate(lines):
            if file_count >= _MAX_FINDINGS_PER_DETECTOR_PER_FILE:
                break

            stripped = raw_line.strip()
            if not stripped or stripped.startswith(("#", "//", "*", "/*")):
                continue

            # Must be in an authentication context (check ±10 lines)
            region_start = max(0, idx - 10)
            region_end = min(len(lines), idx + 11)
            region = "\n".join(lines[region_start:region_end])
            if not _AUTH_CONTEXT_RE.search(region):
                continue

            # Find == or != comparisons
            for m in _BARE_COMPARE_RE.finditer(stripped):
                left, right = m.group(1), m.group(2)

                # At least one side must be a sensitive variable
                if not (_TIMING_SENSITIVE_VARS.match(left) or
                        _TIMING_SENSITIVE_VARS.match(right)):
                    continue

                # Skip if the line already uses a safe compare function
                if _SAFE_COMPARE_RE.search(stripped):
                    continue

                # Skip common false positives
                if left in ("True", "False", "None", "null", "true", "false"):
                    continue
                if right in ("True", "False", "None", "null", "true", "false"):
                    continue

                line_num = idx + 1
                snip_start = max(0, idx - 2)
                snip_end = min(len(lines), idx + 3)
                snippet = "\n".join(lines[snip_start:snip_end])[:_MAX_SNIPPET_CHARS]

                det_id = hashlib.sha256(
                    f"LOGIC-TIMING-001|{fname}|{line_num}".encode()
                ).hexdigest()[:16]

                findings.append(EngineFinding(
                    rule_id="LOGIC-TIMING-001",
                    rule_title="Timing Attack — Non-Constant-Time Comparison",
                    vulnerability_type="Timing Attack",
                    severity="high",
                    confidence=80.0,
                    file_name=fname,
                    line=line_num,
                    description=(
                        f"Variable '{left}' is compared using '==' at line "
                        f"{line_num} in an authentication context. The Python "
                        f"== operator short-circuits on first differing byte, "
                        f"leaking timing information that allows an attacker "
                        f"to brute-force the secret one character at a time."
                    ),
                    category="Backend Security",
                    owasp="A02:2021 — Cryptographic Failures",
                    cwe="CWE-208",
                    matched_pattern=stripped[:200],
                    code_snippet=snippet,
                    impact=(
                        "Attacker can recover secrets (passwords, tokens, "
                        "TOTP codes, API keys) via statistical timing analysis "
                        "with as few as ~100 requests per character position."
                    ),
                    remediation=(
                        "Replace == with hmac.compare_digest() (Python), "
                        "crypto.timingSafeEqual() (Node.js), or equivalent "
                        "constant-time comparison function."
                    ),
                    requires_ai_validation=False,
                    severity_weight=9,
                    exploitability_score="Medium",
                    detection_id=det_id,
                    correlation_flags=["timing_attack_auth_context"],
                    intelligence_modifiers=["logic_timing_attack"],
                    vulnerability_family="timing_attack",
                ))
                file_count += 1
                break  # one finding per line

    return findings


# =====================================================================
#  DETECTOR 3 — Dependency Confusion / Supply Chain  (LOGIC-SUPPLY-*)
# =====================================================================
#
# Scans package manifests (package.json, requirements.txt, Pipfile,
# pyproject.toml, Gemfile, go.mod, pom.xml, *.csproj) for:
#
#   LOGIC-SUPPLY-001  Wildcard / unpinned version ("*", "latest", ">=0")
#   LOGIC-SUPPLY-002  Git dependency without pinned commit hash
#   LOGIC-SUPPLY-003  Dependency confusion risk (private-looking names
#                     without scoped registry, HTTP registries)
#
# Complexity: O(lines) per manifest file.
# =====================================================================

_MANIFEST_EXTENSIONS = frozenset({
    "package.json", "requirements.txt", "pipfile", "pyproject.toml",
    "gemfile", "go.mod", "composer.json", "cargo.toml",
    "build.gradle", "build.sbt",
})

# Wildcard / unpinned patterns
_WILDCARD_VERSION_RE = re.compile(
    r'["\']?\s*(?:\*|latest|>=\s*0|>=\s*0\.0|x\.x\.x|ANY)\s*["\']?',
    re.IGNORECASE,
)

# Git dependency without pinned commit (#sha or @sha or commit=)
_GIT_DEP_RE = re.compile(
    r"git(?:\+https?|@|://)|github\.com/|gitlab\.com/|bitbucket\.org/",
    re.IGNORECASE,
)
_GIT_PINNED_RE = re.compile(
    r"(?:#|@|commit\s*=\s*|ref\s*=\s*|rev\s*=\s*)[0-9a-f]{7,40}",
    re.IGNORECASE,
)

# HTTP (not HTTPS) registry
_HTTP_REGISTRY_RE = re.compile(r"http://", re.IGNORECASE)

# Suspicious private-looking package names (internal-*, @company/* without scope config)
_PRIVATE_NAME_RE = re.compile(
    r'"(internal[-_]|private[-_]|company[-_]|corp[-_]|org[-_])\w+"',
    re.IGNORECASE,
)

# Typosquatting: common misspellings of popular packages
_TYPOSQUAT_TARGETS = {
    # Python
    "reqeusts", "requets", "requsest", "requsets", "request",
    "djnago", "dajngo", "flaask", "flak",
    "numppy", "nunpy", "panadas", "pandsa",
    # JS/Node
    "expresss", "exress", "loadash", "loddash",
    "axois", "axos", "recat", "raect",
    "cros", "croos",
}


def _is_manifest_file(fname: str) -> bool:
    """Check if filename is a package manifest."""
    lower = fname.lower().replace("\\", "/")
    base = lower.rsplit("/", 1)[-1]
    return base in _MANIFEST_EXTENSIONS


def _detect_supply_chain_risks(
    file_lines: Dict[str, List[str]],
) -> List[EngineFinding]:
    """Detector 3: dependency confusion and supply chain risks."""
    findings: List[EngineFinding] = []

    for fname, lines in file_lines.items():
        if not _is_manifest_file(fname):
            continue

        file_count = 0
        for idx, raw_line in enumerate(lines):
            if file_count >= _MAX_FINDINGS_PER_DETECTOR_PER_FILE:
                break

            stripped = raw_line.strip()
            if not stripped or stripped.startswith(("#", "//", "/*")):
                continue

            line_num = idx + 1
            snip_start = max(0, idx - 1)
            snip_end = min(len(lines), idx + 2)

            # --- LOGIC-SUPPLY-001: Wildcard / unpinned version ----------
            if _WILDCARD_VERSION_RE.search(stripped):
                # Avoid false positives on comments or non-version contexts
                if ":" in stripped or "==" in stripped or "=" in stripped or "version" in stripped.lower():
                    snippet = "\n".join(lines[snip_start:snip_end])[:_MAX_SNIPPET_CHARS]
                    det_id = hashlib.sha256(
                        f"LOGIC-SUPPLY-001|{fname}|{line_num}".encode()
                    ).hexdigest()[:16]

                    findings.append(EngineFinding(
                        rule_id="LOGIC-SUPPLY-001",
                        rule_title="Supply Chain — Wildcard / Unpinned Dependency Version",
                        vulnerability_type="Supply Chain Risk",
                        severity="medium",
                        confidence=75.0,
                        file_name=fname,
                        line=line_num,
                        description=(
                            f"Dependency at line {line_num} uses a wildcard or unpinned "
                            f"version specifier. This allows automatic installation of "
                            f"arbitrary future versions, which may contain malicious code "
                            f"injected via package takeover."
                        ),
                        category="DevOps Security",
                        owasp="A06:2021 — Vulnerable and Outdated Components",
                        cwe="CWE-829",
                        matched_pattern=stripped[:200],
                        code_snippet=snippet,
                        impact=(
                            "Arbitrary code execution at install time if a "
                            "malicious version is published to the registry."
                        ),
                        remediation=(
                            "Pin dependencies to exact versions or narrow ranges. "
                            "Use lock files (package-lock.json, Pipfile.lock) and "
                            "verify integrity hashes."
                        ),
                        requires_ai_validation=False,
                        severity_weight=6,
                        exploitability_score="Medium",
                        detection_id=det_id,
                        correlation_flags=["supply_chain_wildcard"],
                        intelligence_modifiers=["logic_supply_chain"],
                        vulnerability_family="supply_chain",
                    ))
                    file_count += 1

            # --- LOGIC-SUPPLY-002: Git dep without pinned commit --------
            if _GIT_DEP_RE.search(stripped) and not _GIT_PINNED_RE.search(stripped):
                snippet = "\n".join(lines[snip_start:snip_end])[:_MAX_SNIPPET_CHARS]
                det_id = hashlib.sha256(
                    f"LOGIC-SUPPLY-002|{fname}|{line_num}".encode()
                ).hexdigest()[:16]

                findings.append(EngineFinding(
                    rule_id="LOGIC-SUPPLY-002",
                    rule_title="Supply Chain — Unpinned Git Dependency",
                    vulnerability_type="Supply Chain Risk",
                    severity="medium",
                    confidence=80.0,
                    file_name=fname,
                    line=line_num,
                    description=(
                        f"Git dependency at line {line_num} is not pinned to a "
                        f"specific commit hash. The repository owner (or an "
                        f"attacker who compromises their account) can push "
                        f"malicious code that will be silently installed."
                    ),
                    category="DevOps Security",
                    owasp="A06:2021 — Vulnerable and Outdated Components",
                    cwe="CWE-829",
                    matched_pattern=stripped[:200],
                    code_snippet=snippet,
                    impact=(
                        "Arbitrary code execution via compromised upstream "
                        "repository. Supply chain attacks of this type have "
                        "affected major open-source ecosystems."
                    ),
                    remediation=(
                        "Pin git dependencies to a specific commit hash: "
                        "git+https://github.com/org/repo@abc1234. "
                        "Never use branch references (main, master) in production."
                    ),
                    requires_ai_validation=False,
                    severity_weight=7,
                    exploitability_score="Medium",
                    detection_id=det_id,
                    correlation_flags=["supply_chain_unpinned_git"],
                    intelligence_modifiers=["logic_supply_chain"],
                    vulnerability_family="supply_chain",
                ))
                file_count += 1

            # --- LOGIC-SUPPLY-003: Dependency confusion risk ------------
            # Private-looking package name or HTTP registry
            if _PRIVATE_NAME_RE.search(stripped):
                snippet = "\n".join(lines[snip_start:snip_end])[:_MAX_SNIPPET_CHARS]
                det_id = hashlib.sha256(
                    f"LOGIC-SUPPLY-003|{fname}|{line_num}".encode()
                ).hexdigest()[:16]

                findings.append(EngineFinding(
                    rule_id="LOGIC-SUPPLY-003",
                    rule_title="Supply Chain — Dependency Confusion Risk",
                    vulnerability_type="Supply Chain Risk",
                    severity="high",
                    confidence=65.0,
                    file_name=fname,
                    line=line_num,
                    description=(
                        f"Package name at line {line_num} looks like an "
                        f"internal/private package but is referenced from a "
                        f"public registry without namespace scoping. An "
                        f"attacker can register the same name on the public "
                        f"registry with a higher version number to hijack "
                        f"installation."
                    ),
                    category="DevOps Security",
                    owasp="A08:2021 — Software and Data Integrity Failures",
                    cwe="CWE-427",
                    matched_pattern=stripped[:200],
                    code_snippet=snippet,
                    impact=(
                        "Arbitrary code execution during dependency "
                        "installation via dependency confusion attack."
                    ),
                    remediation=(
                        "Use scoped namespaces (@company/pkg) for private "
                        "packages. Configure .npmrc or pip.conf to resolve "
                        "private names from your private registry only."
                    ),
                    requires_ai_validation=False,
                    severity_weight=9,
                    exploitability_score="High",
                    detection_id=det_id,
                    correlation_flags=["supply_chain_confusion"],
                    intelligence_modifiers=["logic_supply_chain"],
                    vulnerability_family="supply_chain",
                ))
                file_count += 1

            if _HTTP_REGISTRY_RE.search(stripped) and "registry" in stripped.lower():
                snippet = "\n".join(lines[snip_start:snip_end])[:_MAX_SNIPPET_CHARS]
                det_id = hashlib.sha256(
                    f"LOGIC-SUPPLY-003|{fname}|{line_num}|http".encode()
                ).hexdigest()[:16]

                findings.append(EngineFinding(
                    rule_id="LOGIC-SUPPLY-003",
                    rule_title="Supply Chain — HTTP Package Registry",
                    vulnerability_type="Supply Chain Risk",
                    severity="high",
                    confidence=85.0,
                    file_name=fname,
                    line=line_num,
                    description=(
                        f"Package registry URL at line {line_num} uses "
                        f"unencrypted HTTP. A network attacker can MITM the "
                        f"connection and serve malicious packages."
                    ),
                    category="DevOps Security",
                    owasp="A08:2021 — Software and Data Integrity Failures",
                    cwe="CWE-319",
                    matched_pattern=stripped[:200],
                    code_snippet=snippet,
                    impact=(
                        "Man-in-the-middle substitution of packages during "
                        "install. Full code execution on developer machines "
                        "and CI/CD runners."
                    ),
                    remediation=(
                        "Always use HTTPS for package registry URLs. "
                        "Verify TLS certificate chains."
                    ),
                    requires_ai_validation=False,
                    severity_weight=8,
                    exploitability_score="High",
                    detection_id=det_id,
                    correlation_flags=["supply_chain_http_registry"],
                    intelligence_modifiers=["logic_supply_chain"],
                    vulnerability_family="supply_chain",
                ))
                file_count += 1

            # --- Typosquatting check ------------------------------------
            for typo in _TYPOSQUAT_TARGETS:
                if typo in stripped.lower() and f'"{typo}"' in stripped.lower():
                    snippet = "\n".join(lines[snip_start:snip_end])[:_MAX_SNIPPET_CHARS]
                    det_id = hashlib.sha256(
                        f"LOGIC-SUPPLY-003|{fname}|{line_num}|typo".encode()
                    ).hexdigest()[:16]

                    findings.append(EngineFinding(
                        rule_id="LOGIC-SUPPLY-003",
                        rule_title="Supply Chain — Suspected Typosquatting Package",
                        vulnerability_type="Supply Chain Risk",
                        severity="high",
                        confidence=70.0,
                        file_name=fname,
                        line=line_num,
                        description=(
                            f"Package name '{typo}' at line {line_num} appears "
                            f"to be a typosquatting variant of a popular package. "
                            f"Verify the package name is intentional."
                        ),
                        category="DevOps Security",
                        owasp="A08:2021 — Software and Data Integrity Failures",
                        cwe="CWE-427",
                        matched_pattern=stripped[:200],
                        code_snippet=snippet,
                        impact="Malicious code execution via trojan package.",
                        remediation="Verify the correct package name and update.",
                        requires_ai_validation=False,
                        severity_weight=9,
                        exploitability_score="High",
                        detection_id=det_id,
                        correlation_flags=["supply_chain_typosquat"],
                        intelligence_modifiers=["logic_supply_chain"],
                        vulnerability_family="supply_chain",
                    ))
                    file_count += 1
                    break  # one typo per line

    return findings


# =====================================================================
#  DETECTOR 4 — Dangerous Build Scripts  (LOGIC-SUPPLY-004)
# =====================================================================
#
# Scans package.json "scripts" section for dangerous patterns:
#   - curl/wget piped to sh/bash
#   - eval(...)
#   - node -e with dynamic input
#   - child_process.exec/execSync with external input
#
# Only fires inside the "scripts" block of package.json files.
# =====================================================================

_PIPE_TO_SHELL_RE = re.compile(
    r"(?:curl|wget|fetch)\s+.*\|\s*(?:bash|sh|zsh|node|python|perl)",
    re.IGNORECASE,
)

_EVAL_IN_SCRIPT_RE = re.compile(
    r"\beval\s*\(|\beval\s+[\"']|\$\(.*\)|`.*`",
)

_CHILD_PROCESS_RE = re.compile(
    r"child_process\.exec(?:Sync)?\s*\(|require\s*\(\s*['\"]child_process",
    re.IGNORECASE,
)

_NODE_EXEC_RE = re.compile(
    r"node\s+-e\s+[\"']|node\s+--eval\s+[\"']",
    re.IGNORECASE,
)


def _detect_dangerous_build_scripts(
    file_lines: Dict[str, List[str]],
) -> List[EngineFinding]:
    """Detector 4: dangerous patterns in package.json scripts."""
    findings: List[EngineFinding] = []

    for fname, lines in file_lines.items():
        base = fname.lower().replace("\\", "/").rsplit("/", 1)[-1]
        if base != "package.json":
            continue

        # Find the "scripts" block (simple JSON heuristic — no parser needed)
        in_scripts = False
        brace_depth = 0
        file_count = 0

        for idx, raw_line in enumerate(lines):
            if file_count >= _MAX_FINDINGS_PER_DETECTOR_PER_FILE:
                break

            stripped = raw_line.strip()

            # Detect entry into scripts block
            if '"scripts"' in stripped:
                in_scripts = True
                brace_depth = 0
                # Count opening braces on the same line
                brace_depth += stripped.count("{") - stripped.count("}")
                continue

            if in_scripts:
                brace_depth += stripped.count("{") - stripped.count("}")
                if brace_depth <= 0 and "{" not in stripped:
                    in_scripts = False
                    continue

                # Check for dangerous patterns
                dangerous = False
                pattern_name = ""

                if _PIPE_TO_SHELL_RE.search(stripped):
                    dangerous = True
                    pattern_name = "pipe-to-shell (curl|bash)"
                elif _EVAL_IN_SCRIPT_RE.search(stripped):
                    dangerous = True
                    pattern_name = "eval() in build script"
                elif _CHILD_PROCESS_RE.search(stripped):
                    dangerous = True
                    pattern_name = "child_process.exec in build script"
                elif _NODE_EXEC_RE.search(stripped):
                    dangerous = True
                    pattern_name = "node --eval in build script"

                if dangerous:
                    line_num = idx + 1
                    snip_start = max(0, idx - 2)
                    snip_end = min(len(lines), idx + 3)
                    snippet = "\n".join(lines[snip_start:snip_end])[:_MAX_SNIPPET_CHARS]

                    det_id = hashlib.sha256(
                        f"LOGIC-SUPPLY-004|{fname}|{line_num}".encode()
                    ).hexdigest()[:16]

                    findings.append(EngineFinding(
                        rule_id="LOGIC-SUPPLY-004",
                        rule_title=f"Dangerous Build Script — {pattern_name}",
                        vulnerability_type="Supply Chain Risk",
                        severity="high",
                        confidence=85.0,
                        file_name=fname,
                        line=line_num,
                        description=(
                            f"Build script at line {line_num} contains "
                            f"'{pattern_name}'. This pattern executes "
                            f"arbitrary code during npm install/build, "
                            f"which runs in CI/CD pipelines and developer "
                            f"machines with elevated access."
                        ),
                        category="DevOps Security",
                        owasp="A08:2021 — Software and Data Integrity Failures",
                        cwe="CWE-78",
                        matched_pattern=stripped[:200],
                        code_snippet=snippet,
                        impact=(
                            "Arbitrary code execution on every npm install, "
                            "npm run build, or CI/CD pipeline run. Can "
                            "exfiltrate secrets, inject backdoors, or "
                            "compromise build artifacts."
                        ),
                        remediation=(
                            "Remove shell pipes from build scripts. "
                            "Download dependencies via npm/yarn only. "
                            "If external scripts are required, verify "
                            "integrity via checksums."
                        ),
                        requires_ai_validation=False,
                        severity_weight=10,
                        exploitability_score="High",
                        detection_id=det_id,
                        correlation_flags=["supply_chain_dangerous_script"],
                        intelligence_modifiers=["logic_supply_chain"],
                        vulnerability_family="supply_chain",
                    ))
                    file_count += 1

    return findings


# =====================================================================
#  DETECTOR 5 — Framework Context Validation
# =====================================================================
#
# Post-hoc adjustor: scans existing findings for framework-specific
# rule patterns and verifies the framework is actually present in the
# file (import statement, module usage, etc.).
#
# If the framework is NOT present, confidence is reduced by
# _FRAMEWORK_CONFIDENCE_PENALTY (default 25).  This avoids suppressing
# findings entirely (which risks false negatives) while reducing noise.
#
# O(n) — single pass over findings, with O(1) regex check per finding.
# =====================================================================

_FRAMEWORK_CONFIDENCE_PENALTY = 25.0

# Framework detection rules:
#   key: prefix of rule_ids that require this framework
#   value: (framework_name, regex to confirm framework presence in file)
_FRAMEWORK_SIGNATURES: List[Tuple[str, str, re.Pattern]] = [
    # Flask
    (
        "FLASK",
        "Flask",
        re.compile(r"\bfrom\s+flask\b|\bimport\s+flask\b|from\s+flask", re.IGNORECASE),
    ),
    (
        "DJANGO",
        "Django",
        re.compile(r"\bfrom\s+django\b|\bimport\s+django\b", re.IGNORECASE),
    ),
    (
        "SPRING",
        "Spring",
        re.compile(r"\bimport\s+org\.springframework\b|@SpringBoot|@RestController", re.IGNORECASE),
    ),
    (
        "EXPRESS",
        "Express",
        re.compile(r"require\s*\(\s*['\"]express['\"]\)|from\s+['\"]express['\"]", re.IGNORECASE),
    ),
    (
        "NEXTJS",
        "Next.js",
        re.compile(
            r"\b(?:getServerSideProps|getStaticProps|getStaticPaths)\b|"
            r"from\s+['\"]next/|import\s+.*\s+from\s+['\"]next",
            re.IGNORECASE,
        ),
    ),
    (
        "ELECTRON",
        "Electron",
        re.compile(r"require\s*\(\s*['\"]electron['\"]\)|from\s+['\"]electron['\"]", re.IGNORECASE),
    ),
    (
        "RAILS",
        "Rails",
        re.compile(r"\bclass\s+\w+\s*<\s*(?:ApplicationController|ActiveRecord)", re.IGNORECASE),
    ),
    (
        "FASTAPI",
        "FastAPI",
        re.compile(r"\bfrom\s+fastapi\b|\bimport\s+fastapi\b", re.IGNORECASE),
    ),
    (
        "GIN",
        "Gin",
        re.compile(r'"github\.com/gin-gonic/gin"', re.IGNORECASE),
    ),
]


def _apply_framework_context_validation(
    findings: List[EngineFinding],
    file_contents: Dict[str, str],
) -> int:
    """Detector 5: validate framework context, downgrade confidence
    for framework-specific rules when the framework is not imported.

    Returns the number of findings that were adjusted.
    """
    adjusted_count = 0

    # Build file → content cache (lowered)
    file_content_lower: Dict[str, str] = {
        fname: content.lower() for fname, content in file_contents.items()
    }

    for finding in findings:
        rule_upper = finding.rule_id.upper()

        for prefix, fw_name, fw_regex in _FRAMEWORK_SIGNATURES:
            if not rule_upper.startswith(prefix):
                continue

            # Check if the framework is present in the file
            content = file_contents.get(finding.file_name, "")
            if not content:
                continue

            if fw_regex.search(content):
                continue  # Framework present — no adjustment needed

            # Framework NOT present — downgrade confidence
            base = (
                finding.adjusted_confidence
                if finding.adjusted_confidence is not None
                else finding.confidence
            )
            new_conf = max(5.0, base - _FRAMEWORK_CONFIDENCE_PENALTY)
            finding.adjusted_confidence = round(new_conf, 1)
            finding.intelligence_modifiers.append(
                f"framework_context_miss:{fw_name}"
            )
            finding.correlation_flags.append(
                f"framework:{fw_name}:not_imported"
            )
            adjusted_count += 1
            break  # only first matching prefix

    return adjusted_count


# =====================================================================
#  DETECTOR 6 — Rate-Limit Race Condition  (LOGIC-RACE-002)
# =====================================================================
#
# Heuristic:
#   1. cache.get(key) or similar read
#   2. Followed within N lines by cache.set(key, ...) or similar write
#   3. No atomic operation (incr, decr, atomic, transaction, pipeline,
#      lock, cas, compare_and_swap) between them
#
# This detects TOCTOU in rate-limiting and counter implementations.
# CWE-362: Concurrent Execution Using Shared Resource with Improper
#           Synchronization
# =====================================================================

_CACHE_READ_RE = re.compile(
    r"\b(\w+)\s*=\s*(?:cache|redis|memcache\w*|store|rate_limit\w*)"
    r"\.(?:get|hget|read|fetch)\s*\(",
    re.IGNORECASE,
)

_CACHE_WRITE_RE = re.compile(
    r"(?:cache|redis|memcache\w*|store|rate_limit\w*)"
    r"\.(?:set|hset|put|write|incr_by|setex|setnx)\s*\(",
    re.IGNORECASE,
)

_ATOMIC_OPS_RE = re.compile(
    r"\.(?:incr|decr|atomic|pipeline|multi|cas|compare_and_swap|"
    r"watch|transaction|lock|acquire|setnx|add)\s*\(|"
    r"\bwith\s+\w*lock|asyncio\.Lock|threading\.Lock|"
    r"MULTI\b|EXEC\b",
    re.IGNORECASE,
)

_RATE_LIMIT_WINDOW = 8  # lines between get and set


def _detect_rate_limit_race(
    file_lines: Dict[str, List[str]],
) -> List[EngineFinding]:
    """Detector 6: non-atomic cache get/set patterns."""
    findings: List[EngineFinding] = []

    for fname, lines in file_lines.items():
        file_count = 0
        pending_read: Optional[Tuple[int, str]] = None  # (line_idx, var_name)

        for idx, raw_line in enumerate(lines):
            if file_count >= _MAX_FINDINGS_PER_DETECTOR_PER_FILE:
                break

            stripped = raw_line.strip()
            if not stripped or stripped.startswith(("#", "//", "*", "/*")):
                continue

            # Check for atomic operations → clear pending read
            if _ATOMIC_OPS_RE.search(stripped):
                pending_read = None
                continue

            # Check for cache read
            rm = _CACHE_READ_RE.search(stripped)
            if rm:
                pending_read = (idx, rm.group(1))
                continue

            # Check for cache write within window after a read
            if pending_read is not None:
                read_idx, read_var = pending_read

                # Too far away → expire
                if idx - read_idx > _RATE_LIMIT_WINDOW:
                    pending_read = None
                    continue

                if _CACHE_WRITE_RE.search(stripped):
                    # Found non-atomic get → set
                    line_num = read_idx + 1
                    write_line = idx + 1
                    snip_start = max(0, read_idx - 1)
                    snip_end = min(len(lines), idx + 2)
                    snippet = "\n".join(lines[snip_start:snip_end])[:_MAX_SNIPPET_CHARS]

                    det_id = hashlib.sha256(
                        f"LOGIC-RACE-002|{fname}|{line_num}".encode()
                    ).hexdigest()[:16]

                    findings.append(EngineFinding(
                        rule_id="LOGIC-RACE-002",
                        rule_title="Rate-Limit Race Condition — Non-Atomic Cache Read/Write",
                        vulnerability_type="Race Condition",
                        severity="high",
                        confidence=75.0,
                        file_name=fname,
                        line=line_num,
                        description=(
                            f"Cache read at line {line_num} (variable '{read_var}') "
                            f"is followed by cache write at line {write_line} without "
                            f"an atomic operation. Between the read and write, a "
                            f"concurrent request can read the stale value, causing "
                            f"rate-limit bypass or counter corruption."
                        ),
                        category="Backend Security",
                        owasp="A04:2021 — Insecure Design",
                        cwe="CWE-362",
                        matched_pattern=stripped[:200],
                        code_snippet=snippet,
                        impact=(
                            "Rate-limit bypass allowing unlimited requests. "
                            "Brute-force attacks, resource exhaustion, or "
                            "financial abuse through counter manipulation."
                        ),
                        remediation=(
                            "Use atomic cache operations: Redis INCR/DECR, "
                            "Lua scripting, or WATCH/MULTI/EXEC transactions. "
                            "For in-memory caches, use a lock or atomic counter."
                        ),
                        requires_ai_validation=False,
                        severity_weight=9,
                        exploitability_score="High",
                        detection_id=det_id,
                        correlation_flags=["rate_limit_race_condition"],
                        intelligence_modifiers=["logic_rate_limit_race"],
                        vulnerability_family="race_condition",
                    ))
                    file_count += 1
                    pending_read = None  # consumed

    return findings


# =====================================================================
#  PUBLIC API — Main Entry Point
# =====================================================================


def apply_logic_detectors(
    findings: List[EngineFinding],
    file_contents: Dict[str, str],
) -> List[EngineFinding]:
    """Run all logic detectors and return enriched finding list.

    Called from pipeline.py AFTER rule intelligence, BEFORE clustering.

    Args:
        findings: Current list of EngineFinding objects (mutated in-place
                  for framework context validation).
        file_contents: Dict mapping file_name → raw file content.

    Returns:
        Updated findings list with synthetic findings appended and
        framework context adjustments applied in-place.

    Complexity: O(n) where n = total lines across all files.
    """
    import time
    start = time.monotonic()

    # Pre-compute line-split view (reused by all detectors)
    file_lines: Dict[str, List[str]] = {
        fname: content.split("\n")
        for fname, content in file_contents.items()
    }

    # --- Run file-level detectors (emit synthetic findings) ----------
    new_findings: List[EngineFinding] = []

    race_findings = _detect_async_race_conditions(file_lines)
    new_findings.extend(race_findings)

    timing_findings = _detect_timing_attacks(file_lines)
    new_findings.extend(timing_findings)

    supply_findings = _detect_supply_chain_risks(file_lines)
    new_findings.extend(supply_findings)

    build_findings = _detect_dangerous_build_scripts(file_lines)
    new_findings.extend(build_findings)

    rate_findings = _detect_rate_limit_race(file_lines)
    new_findings.extend(rate_findings)

    # --- Run finding-level adjustors (modify existing findings) ------
    fw_adjusted = _apply_framework_context_validation(
        findings, file_contents
    )

    # Merge synthetic findings into the main list
    findings.extend(new_findings)

    elapsed_ms = (time.monotonic() - start) * 1000

    # Log summary
    counts = defaultdict(int)
    for f in new_findings:
        counts[f.rule_id] += 1

    if new_findings or fw_adjusted:
        logger.info(
            "Logic Detectors: emitted %d findings in %.1f ms "
            "(RACE-001=%d, TIMING-001=%d, SUPPLY-001=%d, SUPPLY-002=%d, "
            "SUPPLY-003=%d, SUPPLY-004=%d, RACE-002=%d, fw_adjusted=%d).",
            len(new_findings),
            elapsed_ms,
            counts.get("LOGIC-RACE-001", 0),
            counts.get("LOGIC-TIMING-001", 0),
            counts.get("LOGIC-SUPPLY-001", 0),
            counts.get("LOGIC-SUPPLY-002", 0),
            counts.get("LOGIC-SUPPLY-003", 0),
            counts.get("LOGIC-SUPPLY-004", 0),
            counts.get("LOGIC-RACE-002", 0),
            fw_adjusted,
        )
    else:
        logger.debug(
            "Logic Detectors: no findings emitted (%.1f ms).", elapsed_ms
        )

    return findings


def generate_logic_detector_summary(
    findings: List[EngineFinding],
) -> Dict:
    """Generate a summary of logic detector findings for reports.

    Returns a dict with counts per detector type and total.
    """
    logic_rule_ids = {
        "LOGIC-RACE-001", "LOGIC-RACE-002",
        "LOGIC-TIMING-001",
        "LOGIC-SUPPLY-001", "LOGIC-SUPPLY-002",
        "LOGIC-SUPPLY-003", "LOGIC-SUPPLY-004",
    }

    counts: Dict[str, int] = defaultdict(int)
    affected_files: Set[str] = set()

    for f in findings:
        if f.rule_id in logic_rule_ids:
            counts[f.rule_id] += 1
            affected_files.add(f.file_name)

    total = sum(counts.values())

    return {
        "total_logic_findings": total,
        "detector_counts": dict(counts),
        "affected_files": sorted(affected_files),
        "detectors_active": len([v for v in counts.values() if v > 0]),
    }
