"""
Rule Intelligence Orchestrator — deterministic post-detection metadata layer.

Consumes 6 previously-unused YAML rule metadata fields to enrich findings
with contextual intelligence AFTER detection but BEFORE deduplication and
severity normalization.

Pipeline position: Detection → **Rule Intelligence** → Dedup → Severity → AI

Capabilities:
    1. Detection Layer Activation — flags layer-2 (contextual) findings
    2. Attack Surface Amplification — boosts weight for API/internal surfaces
    3. Line-Level Anti-Pattern Evaluation — proximity-based suppression refinement
    4. Related Rules Correlation — cross-finding linkage flags
    5. Privilege Context Calibration — adjusts weight for privilege escalation
    6. Multi-Function Chain Detection — flags chain-matching findings
    7. Confidence Recalibration — synthesizes all modifiers into adjusted scores

Logic Detectors (file-level, emit synthetic findings):
    L1. Multi-Tenant Isolation Bypass (LOGIC-MT-001) — missing tenant scope
    L2. IDOR Detection (LOGIC-IDOR-001) — unscoped direct object references
    L3. Header Privilege Escalation (LOGIC-PRIV-001) — forgeable authorization

Constraints:
    - Deterministic: NO AI, NO randomness, NO external calls
    - Performance: O(n) per finding, O(n log n) for correlation indexing
    - Thread-safe: operates on mutable EngineFinding objects in main process
    - No AST parsing or taint analysis engine
"""

import hashlib
import logging
import re
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from engine.models import EngineFinding

logger = logging.getLogger("engine.rule_intelligence")

# ─── Constants ────────────────────────────────────────────────────────

# Anti-pattern proximity: lines within this radius are considered "near".
# Configurable — some framework sanitizers span 8-12 lines.
DEFAULT_ANTI_PATTERN_LINE_RADIUS = 8

# Confidence adjustment bounds (0-100 scale, clamped to safe range)
MIN_CONFIDENCE = 0.0
MAX_CONFIDENCE = 100.0

# Conservative modifier weights for confidence recalibration.
# Positive values = confidence boost, negative = suppression.
# IMPORTANT: These operate on the 0-100 confidence scale.
# Kept conservative to avoid inflating risk scores.
MODIFIER_WEIGHTS = {
    "detection_layer_2_corroborated": 4.0,  # layer-2 with layer-1 support
    "detection_layer_2_isolated": -5.0,     # layer-2 without corroboration
    "attack_surface_api": 2.0,              # API surface (conservative)
    "attack_surface_internal": 3.0,         # internal surface
    "privilege_escalation": 3.0,            # escalation vector present
    "admin_only_risk": 1.5,                 # admin-only — niche but real
    "no_auth_required": 2.0,                # no-auth → broader attack surface
    "chain_match": 3.0,                     # multi-function chain evidence
    "correlated_rule": 2.0,                 # related rule also triggered
    "financial_impact": 2.0,                # business: financial impact
    "data_exposure": 1.5,                   # business: data exposure
    "compliance_relevant": 1.0,             # business: compliance
    "line_anti_pattern": -12.0,             # line-level anti-pattern penalty
    "taint_path_match": 2.0,                # probable taint path evidence
    # Logic detector modifiers (synthetic findings — confidence set at creation)
    "logic_mt_isolation_bypass": 0.0,        # LOGIC-MT-001: confidence pre-set
    "logic_idor_unscoped": 0.0,              # LOGIC-IDOR-001: confidence pre-set
    "logic_header_privilege_trust": 0.0,     # LOGIC-PRIV-001: confidence pre-set
}

# Severity weight adjustment caps.
# Conservative: max +3 boost to prevent double-counting with
# exploitability_factor already baked into severity.py's formula.
MAX_SEVERITY_WEIGHT_BOOST = 3
MAX_SEVERITY_WEIGHT_PENALTY = -3

# ─── Logic Detector Constants ────────────────────────────────────────

# Max synthetic findings per file per detector (caps noise)
_LOGIC_MAX_PER_FILE = 5

# ── Multi-Tenant Isolation (LOGIC-MT-001) ──
_MT_TENANT_INDICATORS = re.compile(
    r'\btenant[_\-]?id\b|\borg[_\-]?id\b|\borganization[_\-]?id\b|'
    r'\bcurrent[_\-]?tenant\b|\baccount[_\-]?id\b|\bworkspace[_\-]?id\b',
)
_MT_QUERY_PATTERNS = re.compile(
    r'\.query\s*\(|\.filter\s*\(|\.filter_by\s*\(|'
    r'\.find\s*\(|\.find_one\s*\(|\.find_many\s*\(|'
    r'\.objects\s*\.\s*(?:filter|get|all|exclude)\s*\(|'
    r'\bdb\s*\.\s*(?:execute|session)\b',
)
_MT_SCOPE_TERMS = re.compile(
    r'\btenant[_\-]?id\b|\borg[_\-]?id\b|\borganization[_\-]?id\b|'
    r'\bcurrent[_\-]?tenant\b|\baccount[_\-]?id\b|\bworkspace[_\-]?id\b',
)
# Forward-only scope check: query line + next N continuation lines.
# Only looks FORWARD from the query to catch multi-line filter chains
# without being fooled by variable declarations above the query.
_MT_SCOPE_FORWARD_LINES = 3

# ── IDOR (LOGIC-IDOR-001) ──
_IDOR_ROUTE_PATTERN = re.compile(
    r'(?:@\w+\.(?:route|get|post|put|patch|delete)\s*\(\s*["\']|'
    r'\b(?:router|app)\.(?:get|post|put|patch|delete)\s*\(\s*["\'])'
    r'([^"\']+)["\']',
    re.IGNORECASE,
)
_IDOR_PATH_PARAM = re.compile(
    r'<(?:int|string|float)?:?(\w*(?:id|pk|uuid)\w*)>|'
    r'\{(\w*(?:id|pk|uuid)\w*)\}|'
    r':(\w*(?:id|pk|uuid)\w*)\b',
    re.IGNORECASE,
)
_IDOR_DIRECT_QUERY = re.compile(
    r'\.get\s*\(|\.query\.get\s*\(|\.filter_by\s*\(\s*(?:id|pk)\s*=|'
    r'\.objects\.get\s*\(\s*(?:id|pk)\s*=|\.find_one\s*\(\s*\{["\']_?id["\']',
    re.IGNORECASE,
)
_IDOR_AUTHZ_CHECK = re.compile(
    r'\bauthoriz|\bpermission|\bowner[_\-]?id\b|\buser[_\-]?id\b|'
    r'\bcheck_access|\bhas_permission|\bverify_owner|\bcurrent_user\b|'
    r'\b(?:login|permission)_required\b|\.has_perm\s*\(',
    re.IGNORECASE,
)
_IDOR_FUNC_BODY_LINES = 25

# ── Header Privilege (LOGIC-PRIV-001) ──
_HEADER_PRIV_READ = re.compile(
    r'request\.headers\.get\s*\(\s*["\']'
    r'(x[_\-]?is[_\-]?admin|x[_\-]?role|x[_\-]?admin|'
    r'x[_\-]?permissions?|x[_\-]?user[_\-]?role|x[_\-]?auth[_\-]?level|'
    r'x[_\-]?privilege|x[_\-]?access[_\-]?level|x[_\-]?is[_\-]?staff)',
    re.IGNORECASE,
)
_HEADER_PRIV_BRACKET = re.compile(
    r'request\.headers\s*\[\s*["\']'
    r'(x[_\-]?is[_\-]?admin|x[_\-]?role|x[_\-]?admin|'
    r'x[_\-]?permissions?|x[_\-]?user[_\-]?role|x[_\-]?auth[_\-]?level|'
    r'x[_\-]?privilege|x[_\-]?access[_\-]?level|x[_\-]?is[_\-]?staff)',
    re.IGNORECASE,
)
_PRIV_ASSIGNMENT = re.compile(
    r'(?:is[_\-]?admin|is[_\-]?superuser|g\.is[_\-]?admin|g\.role|'
    r'user[_\-]?role|has[_\-]?privilege|access[_\-]?level|'
    r'permission[_\-]?level|is[_\-]?staff)\s*=',
    re.IGNORECASE,
)
_PRIV_CONDITION = re.compile(
    r'\bif\b.*(?:is[_\-]?admin|is[_\-]?superuser|g\.is[_\-]?admin|'
    r'g\.role|role\s*(?:==|!=|in\b)|has[_\-]?privilege)',
    re.IGNORECASE,
)
_HEADER_PRIV_SCAN_RADIUS = 15

# ── Multi-Tenant List Comprehension (LOGIC-MT-009) ──
_MT009_TENANT_INDICATORS = (
    "tenant_id", "g.tenant_id", "org_id", "workspace_id",
)
_MT009_LISTCOMP_PATTERN = re.compile(
    r'\[\s*\w+\s+for\s+\w+\s+in\s+\w+\s+if\s+(.*?)\]',
    re.DOTALL,
)
_MT009_SCOPE_TERMS = (
    "tenant_id", "g.tenant_id", "org_id", "workspace_id",
)
_MT009_ANTI_PATTERNS = (
    "# nosec", "admin_override", "system_wide_query",
)
_MT009_MAX_PER_FILE = 3


# ─── Capability 1: Detection Layer Activation ────────────────────────


def _apply_detection_layer(
    finding: EngineFinding,
    rule_meta: dict,
    file_has_layer1: bool = False,
) -> None:
    """Score findings from layer-2 (contextual/behavioral) rules.

    Layer 2 rules are behavioral detections. Their confidence depends on
    whether a layer-1 (direct pattern) rule ALSO triggered in the same file:
    - Corroborated (layer-1 present): boost confidence — the behavioral
      detection is backed by a concrete pattern match.
    - Isolated (no layer-1): reduce confidence — behavioral detection
      alone is less reliable without direct evidence.
    """
    detection_layer = rule_meta.get("detection_layer", 1)
    if detection_layer >= 2:
        if file_has_layer1:
            finding.intelligence_modifiers.append("detection_layer_2_corroborated")
            finding.correlation_flags.append(
                f"layer:{detection_layer}:corroborated_by_layer1"
            )
        else:
            finding.intelligence_modifiers.append("detection_layer_2_isolated")
            finding.correlation_flags.append(
                f"layer:{detection_layer}:isolated_no_layer1_support"
            )


# ─── Capability 2: Attack Surface Amplification ─────────────────────


def _apply_attack_surface(
    finding: EngineFinding,
    rule_meta: dict,
) -> None:
    """Boost or flag based on attack_surface_type.

    API and internal surfaces typically represent higher-risk exposure
    than standard web endpoints due to less filtering / lower visibility.
    """
    surface = rule_meta.get("attack_surface_type", "web")

    if surface == "api":
        finding.intelligence_modifiers.append("attack_surface_api")
        finding.correlation_flags.append("surface:api:higher_exposure")
    elif surface == "internal":
        finding.intelligence_modifiers.append("attack_surface_internal")
        finding.correlation_flags.append("surface:internal:lateral_movement_risk")
    elif surface == "mobile":
        finding.correlation_flags.append("surface:mobile:client_side")


# ─── Capability 3: Line-Level Anti-Pattern Evaluation ────────────────


def _apply_line_level_anti_pattern(
    finding: EngineFinding,
    file_lines: Optional[List[str]],
    anti_patterns: tuple,
    radius: int = DEFAULT_ANTI_PATTERN_LINE_RADIUS,
) -> None:
    """Check if any anti-pattern literal appears near the finding's line.

    Unlike the existing file-level suppression in detection_engine.py
    (which blanket-suppresses all matches if ANY anti-pattern is ANYWHERE
    in the file), this performs proximity-based evaluation:
    - Checks ± radius lines around the finding line (default 8)
    - Applies a confidence penalty rather than full suppression
    - Records the specific anti-pattern that matched nearby

    This runs AFTER detection's file-level check, so it only fires on
    findings that survived the file-level filter.

    The radius is configurable because some framework sanitizers
    (e.g. Django CSRF middleware, Express helmet()) span 8-12 lines.

    IMPORTANT: file_lines MUST come from the original file content,
    not from the chunked streaming buffer. When file_contents is
    provided to apply_rule_intelligence(), this uses the real file
    lines. When not provided, it falls back to snippet-based lines
    which have lower fidelity.
    """
    if not anti_patterns or file_lines is None:
        return

    line_idx = finding.line - 1  # 0-based
    start = max(0, line_idx - radius)
    end = min(len(file_lines), line_idx + radius + 1)

    nearby_text = "\n".join(file_lines[start:end]).lower()

    for ap in anti_patterns:
        ap_lower = ap.lower()
        # Try literal match first (fast path)
        if ap_lower in nearby_text:
            finding.intelligence_modifiers.append("line_anti_pattern")
            finding.correlation_flags.append(
                f"anti_pattern_nearby:{ap[:60]}:lines_{start+1}-{end}"
            )
            return
        # Try as regex (anti_patterns may be regex strings)
        try:
            if re.search(ap, nearby_text, re.IGNORECASE):
                finding.intelligence_modifiers.append("line_anti_pattern")
                finding.correlation_flags.append(
                    f"anti_pattern_nearby:{ap[:60]}:lines_{start+1}-{end}"
                )
                return
        except re.error:
            pass  # Not a valid regex, literal check was sufficient


# ─── Capability 4: Related Rules Correlation ─────────────────────────


def _apply_related_rules_correlation(
    finding: EngineFinding,
    related_rules: tuple,
    findings_by_file: Dict[str, List[EngineFinding]],
    all_rule_ids_triggered: Set[str],
) -> None:
    """Check if any rule referenced in related_rules also triggered.

    Two correlation modes:
    1. Same-file correlation: related rule triggered in the SAME file
       → strongest signal (co-located vulnerabilities compound risk)
    2. Cross-file correlation: related rule triggered in ANY file
       → weaker signal but still meaningful for attack chain analysis
    """
    if not related_rules:
        return

    file_findings = findings_by_file.get(finding.file_name, [])
    file_rule_ids = {f.rule_id for f in file_findings if f.rule_id != finding.rule_id}

    for related_id in related_rules:
        if not related_id:
            continue

        if related_id in file_rule_ids:
            # Same-file correlation — strong signal
            finding.intelligence_modifiers.append("correlated_rule")
            finding.correlation_flags.append(
                f"related_rule_same_file:{related_id}"
            )
        elif related_id in all_rule_ids_triggered:
            # Cross-file correlation — weaker signal
            finding.correlation_flags.append(
                f"related_rule_cross_file:{related_id}"
            )


# ─── Capability 5: Privilege Context Calibration ─────────────────────


def _apply_privilege_context(
    finding: EngineFinding,
    rule_meta: dict,
) -> None:
    """Adjust weight based on privilege_context_flags.

    Flags examined:
    - requires_auth_context: if False → no auth needed → higher risk
    - admin_only_risk: if True → exploitable only by admins → niche risk
    - escalation_vector: non-empty → active privilege escalation path
    """
    pcf = rule_meta.get("privilege_context_flags", ())

    # Convert tuple of pairs back to dict for easy lookup
    if isinstance(pcf, (tuple, list)):
        pcf_dict = dict(pcf)
    elif isinstance(pcf, dict):
        pcf_dict = pcf
    else:
        return

    if not pcf_dict:
        return

    # No auth required → higher exploitability
    requires_auth = pcf_dict.get("requires_auth_context", True)
    if requires_auth is False or str(requires_auth).lower() == "false":
        finding.intelligence_modifiers.append("no_auth_required")
        finding.correlation_flags.append("privilege:no_auth_required")

    # Admin-only risk → niche but real. Conservative: only flag,
    # the weight (1.5) is intentionally low to avoid over-inflation.
    # We do NOT attempt path-based or decorator-based admin detection
    # here — that's the rule's responsibility via privilege_context_flags.
    # This layer trusts the YAML metadata as authored by the rule writer.
    admin_risk = pcf_dict.get("admin_only_risk", False)
    if admin_risk is True or str(admin_risk).lower() == "true":
        finding.intelligence_modifiers.append("admin_only_risk")
        finding.correlation_flags.append("privilege:admin_only_risk")

    # Escalation vector present → direct path to privilege escalation.
    # Conservative amplification: capped at +3 confidence via MODIFIER_WEIGHTS
    # to prevent inflating already-high-exploitability findings.
    escalation = pcf_dict.get("escalation_vector", "")
    if escalation and str(escalation).strip():
        finding.intelligence_modifiers.append("privilege_escalation")
        finding.correlation_flags.append(
            f"privilege:escalation:{str(escalation)[:100]}"
        )


# ─── Capability 6: Multi-Function Chain Detection ────────────────────


def _apply_chain_detection(
    finding: EngineFinding,
    rule_meta: dict,
    file_content_lower: Optional[str],
) -> None:
    """Check if multi_function_chain_patterns have evidence in the file.

    Chain patterns describe expected data flows like:
        "request.args.get('url') -> validate_url() -> requests.get(url)"

    We split on ' -> ' and check if each component (as a simplified
    substring or keyword) appears in the file content. If ALL components
    of any chain are present, it flags a chain match.

    This is a lightweight heuristic, NOT taint analysis.
    """
    chains = rule_meta.get("multi_function_chain_patterns", ())
    if not chains or file_content_lower is None:
        return

    for chain_desc in chains:
        if not chain_desc or " -> " not in str(chain_desc):
            continue

        components = [c.strip() for c in str(chain_desc).split(" -> ") if c.strip()]
        if len(components) < 2:
            continue

        # Extract keywords from each component for substring matching
        all_found = True
        for component in components:
            # Extract the function/method name (simplified: take first word-like part)
            keywords = re.findall(r'[a-zA-Z_]\w*(?:\.\w+)*', component)
            if not keywords:
                continue

            # Check if any keyword from this component appears in file
            component_found = False
            for kw in keywords:
                if kw.lower() in file_content_lower:
                    component_found = True
                    break

            if not component_found:
                all_found = False
                break

        if all_found:
            finding.intelligence_modifiers.append("chain_match")
            finding.correlation_flags.append(
                f"chain_detected:{str(chain_desc)[:120]}"
            )
            return  # One chain match is sufficient


# ─── Capability 6b: Taint Path Evidence Detection ────────────────────


def _apply_taint_path_evidence(
    finding: EngineFinding,
    rule_meta: dict,
    file_content_lower: Optional[str],
) -> None:
    """Check if probable_taint_paths have evidence in the file content.

    Each taint path has (source, sink, through). We check for substring
    presence of source and sink keywords in the file.
    """
    paths = rule_meta.get("probable_taint_paths", ())
    if not paths or file_content_lower is None:
        return

    for path_entry in paths:
        if isinstance(path_entry, (tuple, list)) and len(path_entry) >= 2:
            source, sink = str(path_entry[0]), str(path_entry[1])
        elif isinstance(path_entry, dict):
            source = str(path_entry.get("source", ""))
            sink = str(path_entry.get("sink", ""))
        else:
            continue

        if not source or not sink:
            continue

        # Extract first significant identifier from source and sink
        source_kws = re.findall(r'[a-zA-Z_]\w*(?:\.\w+)*', source)
        sink_kws = re.findall(r'[a-zA-Z_]\w*(?:\.\w+)*', sink)

        source_found = any(kw.lower() in file_content_lower for kw in source_kws)
        sink_found = any(kw.lower() in file_content_lower for kw in sink_kws)

        if source_found and sink_found:
            finding.intelligence_modifiers.append("taint_path_match")
            finding.correlation_flags.append(
                f"taint_evidence:{source[:50]}->{sink[:50]}"
            )
            return  # One match is sufficient


# ─── Capability 6c: Business Logic Indicator ─────────────────────────


def _apply_business_logic(
    finding: EngineFinding,
    rule_meta: dict,
) -> None:
    """Flag findings with business logic risk indicators.

    Checks financial_impact, data_exposure_risk, compliance_relevant
    from business_logic_indicator metadata.
    """
    bli = rule_meta.get("business_logic_indicator", ())

    # Convert tuple of pairs back to dict
    if isinstance(bli, (tuple, list)):
        bli_dict = dict(bli) if bli else {}
    elif isinstance(bli, dict):
        bli_dict = bli
    else:
        return

    if not bli_dict:
        return

    fin = bli_dict.get("financial_impact", False)
    if fin is True or str(fin).lower() == "true":
        finding.intelligence_modifiers.append("financial_impact")
        finding.correlation_flags.append("business:financial_impact")

    data = bli_dict.get("data_exposure_risk", False)
    if data is True or str(data).lower() == "true":
        finding.intelligence_modifiers.append("data_exposure")
        finding.correlation_flags.append("business:data_exposure_risk")

    comp = bli_dict.get("compliance_relevant", False)
    if comp is True or str(comp).lower() == "true":
        finding.intelligence_modifiers.append("compliance_relevant")
        finding.correlation_flags.append("business:compliance_relevant")


# ─── Capability 7: Confidence Recalibration ──────────────────────────


def _recalibrate_confidence(finding: EngineFinding) -> None:
    """Synthesize all intelligence_modifiers into adjusted confidence
    and severity weight.

    Formula:
        adjusted_confidence = clamp(
            base_confidence + sum(modifier_weights),
            0.0,
            100.0
        )

    Never negative. Never > 100.

    Severity weight recalibration is CONSERVATIVE to avoid double-counting:
    - severity.py already multiplies by exploitability_factor (High=1.0, Med=0.7)
    - We ONLY adjust severity_weight when exploitability is NOT already High,
      preventing double-amplification.
    - MAX_SEVERITY_WEIGHT_BOOST is capped at +3 (vs base max of 15).

    The original confidence and severity_weight are preserved —
    adjusted values are stored in separate fields so downstream
    stages (severity.py) can use the enriched values.
    """
    if not finding.intelligence_modifiers:
        return

    # ── Confidence adjustment ───────────────────────────────────────
    boosts = 0.0
    suppressions = 0.0
    for modifier in finding.intelligence_modifiers:
        w = MODIFIER_WEIGHTS.get(modifier, 0.0)
        if w > 0:
            boosts += w
        else:
            suppressions += w  # negative value

    delta = boosts + suppressions  # suppressions are already negative
    base_conf = finding.confidence  # 0-100 scale
    adjusted = max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, base_conf + delta))
    finding.adjusted_confidence = round(adjusted, 1)

    # ── Severity weight adjustment ──────────────────────────────────
    # Guard against double-counting with exploitability_factor:
    # If exploitability is already "High" (factor=1.0), we apply a
    # dampened boost (÷4 instead of ÷3) since the score is already
    # at maximum exploitability multiplier.
    exploit_is_high = (
        finding.exploitability_score.lower() == "high"
        if finding.exploitability_score else False
    )
    divisor = 4.0 if exploit_is_high else 3.0

    weight_delta = 0
    if boosts > 0:
        weight_delta += min(int(boosts / divisor), MAX_SEVERITY_WEIGHT_BOOST)
    if suppressions < 0:
        weight_delta += max(int(suppressions / divisor), MAX_SEVERITY_WEIGHT_PENALTY)

    if weight_delta != 0:
        adjusted_weight = max(1, min(15, finding.severity_weight + weight_delta))
        finding.adjusted_severity_weight = adjusted_weight


# ─── Rule Metadata Helper ────────────────────────────────────────────


def _build_rule_meta_index(
    rule_index,
) -> Dict[str, dict]:
    """Build a rule_id → metadata dict from the RuleIndex.

    Extracts the 6 intelligence fields from each EngineRule into a flat
    dict for quick lookup during finding processing.
    """
    meta_index: Dict[str, dict] = {}
    for rule in rule_index.all_rules:
        meta_index[rule.rule_id] = {
            "detection_layer": rule.detection_layer,
            "attack_surface_type": rule.attack_surface_type,
            "privilege_context_flags": rule.privilege_context_flags,
            "multi_function_chain_patterns": rule.multi_function_chain_patterns,
            "probable_taint_paths": rule.probable_taint_paths,
            "business_logic_indicator": rule.business_logic_indicator,
            "anti_patterns": rule.anti_patterns,
            "related_rules": rule.related_rules,
            "vulnerability_family": rule.vulnerability_family,
        }
    return meta_index


# ─── File Content Cache ──────────────────────────────────────────────


def _build_file_content_index(
    findings: List[EngineFinding],
) -> Dict[str, Optional[str]]:
    """Build file_name → lowered content from code_snippet context.

    Since we don't have raw file content at this pipeline stage,
    we use the code_snippet as a proxy for line-level analysis.
    For chain/taint detection, we combine all snippets from the same file.
    """
    file_snippets: Dict[str, List[str]] = defaultdict(list)
    for f in findings:
        if f.code_snippet:
            file_snippets[f.file_name].append(f.code_snippet)

    return {
        fname: "\n".join(snippets).lower()
        for fname, snippets in file_snippets.items()
    }


def _build_file_lines_index(
    findings: List[EngineFinding],
) -> Dict[str, List[str]]:
    """Build file_name → list of lines from code snippets.

    Used for line-level anti-pattern proximity checking.
    """
    file_snippets: Dict[str, List[str]] = defaultdict(list)
    for f in findings:
        if f.code_snippet:
            file_snippets[f.file_name].append(f.code_snippet)

    return {
        fname: "\n".join(snippets).split("\n")
        for fname, snippets in file_snippets.items()
    }


# ─── Logic Detector 1: Multi-Tenant Isolation Bypass (LOGIC-MT-001) ──


def _detect_multitenant_isolation_bypass(
    file_content_lower: Dict[str, str],
    file_lines: Dict[str, List[str]],
) -> List[EngineFinding]:
    """Detect data access without tenant scope in multi-tenant files.

    Strategy (single pass per file, O(n)):
    1. Skip files without multi-tenant indicators (tenant_id, org_id, etc.)
    2. In remaining files, scan each line for data access patterns
    3. For each match, check ±_MT_SCOPE_RADIUS lines for tenant scope terms
    4. Missing scope → emit synthetic finding (severity=high, confidence=60)

    CWE-284: Improper Access Control
    OWASP A01:2021: Broken Access Control
    """
    new_findings: List[EngineFinding] = []

    for fname, content_lower in file_content_lower.items():
        # Quick reject: not a multi-tenant file
        if not _MT_TENANT_INDICATORS.search(content_lower):
            continue

        lines = file_lines.get(fname)
        if not lines:
            continue

        file_count = 0
        for line_idx, line in enumerate(lines):
            if file_count >= _LOGIC_MAX_PER_FILE:
                break

            line_stripped = line.strip()
            # Skip empty lines and comments
            if not line_stripped or line_stripped.startswith(
                ("#", "//", "*", "/*", "'''", '"""')
            ):
                continue

            line_lower = line_stripped.lower()
            if not _MT_QUERY_PATTERNS.search(line_lower):
                continue

            # Check the query line + forward continuation lines for
            # tenant scope terms. Forward-only avoids false negatives
            # from variable declarations above the query.
            scope_start = line_idx
            scope_end = min(
                len(lines), line_idx + _MT_SCOPE_FORWARD_LINES + 1
            )
            nearby = "\n".join(lines[scope_start:scope_end]).lower()

            if _MT_SCOPE_TERMS.search(nearby):
                continue  # Tenant scope present in query chain — OK

            # Emit finding
            line_num = line_idx + 1
            snip_start = max(0, line_idx - 2)
            snip_end = min(len(lines), line_idx + 3)
            snippet = "\n".join(lines[snip_start:snip_end])[:800]

            det_id = hashlib.sha256(
                f"LOGIC-MT-001|{fname}|{line_num}".encode()
            ).hexdigest()[:16]

            new_findings.append(EngineFinding(
                rule_id="LOGIC-MT-001",
                rule_title="Multi-Tenant Isolation Bypass — Missing Tenant Scope",
                vulnerability_type="Broken Access Control",
                severity="high",
                confidence=60.0,
                file_name=fname,
                line=line_num,
                description=(
                    f"Data access at line {line_num} lacks tenant_id/org_id "
                    f"scope filtering in its query chain (checked "
                    f"{_MT_SCOPE_FORWARD_LINES} continuation lines) in a "
                    f"file with multi-tenant context. Could allow "
                    f"cross-tenant data leakage."
                ),
                category="Backend Security",
                owasp="A01:2021 — Broken Access Control",
                cwe="CWE-284",
                matched_pattern=line_stripped[:200],
                code_snippet=snippet,
                impact=(
                    "Cross-tenant data leakage or modification. "
                    "Attacker can read, update, or delete records "
                    "belonging to other tenants."
                ),
                remediation=(
                    "Add explicit tenant_id filtering to all data access "
                    "operations. Use a base query class or middleware that "
                    "injects tenant scope automatically."
                ),
                requires_ai_validation=False,
                severity_weight=9,
                exploitability_score="High",
                detection_id=det_id,
                correlation_flags=["missing_tenant_scope"],
                intelligence_modifiers=["logic_mt_isolation_bypass"],
                vulnerability_family="multi_tenant_isolation",
            ))
            file_count += 1

    return new_findings


# ─── Logic Detector 2: IDOR Detection (LOGIC-IDOR-001) ──────────────


def _detect_idor_patterns(
    file_content_lower: Dict[str, str],
    file_lines: Dict[str, List[str]],
) -> List[EngineFinding]:
    """Detect insecure direct object references in route handlers.

    Strategy (single pass per file, O(n)):
    1. Find route decorators/handlers with ID path parameters
       (Flask <int:id>, FastAPI {id}, Express :id)
    2. Scan function body (next ~25 lines) for direct database access
    3. Check body for authorization/ownership validation patterns
    4. No authorization → emit finding (severity=critical, confidence=70)

    CWE-639: Authorization Bypass Through User-Controlled Key
    OWASP A01:2021: Broken Access Control
    """
    new_findings: List[EngineFinding] = []

    for fname, content_lower in file_content_lower.items():
        lines = file_lines.get(fname)
        if not lines:
            continue

        file_count = 0
        line_idx = 0
        while line_idx < len(lines) and file_count < _LOGIC_MAX_PER_FILE:
            line = lines[line_idx]
            line_lower = line.strip().lower()

            # Look for route decorator/handler
            route_match = _IDOR_ROUTE_PATTERN.search(line_lower)
            if not route_match:
                line_idx += 1
                continue

            route_path = route_match.group(1)
            param_match = _IDOR_PATH_PARAM.search(route_path)
            if not param_match:
                line_idx += 1
                continue

            param_name = (
                param_match.group(1) or param_match.group(2)
                or param_match.group(3)
            ).lower()

            # Scan function body — stop at next function/class/decorator
            # boundary to avoid bleeding into adjacent functions.
            body_start = line_idx + 1
            body_end = min(len(lines), line_idx + _IDOR_FUNC_BODY_LINES + 1)
            for bi in range(body_start + 1, body_end):
                s = lines[bi].strip()
                if s and s[:1] not in (" ", "\t", "") and (
                    s.startswith(("def ", "class ", "async def "))
                    or (s.startswith("@") and not s.startswith(("@property",)))
                    or s.startswith(("function ", "async function "))
                ):
                    body_end = bi
                    break
            body_text = "\n".join(lines[body_start:body_end]).lower()

            # Must have direct object access
            if not _IDOR_DIRECT_QUERY.search(body_text):
                line_idx += 1
                continue

            # Check for authorization patterns
            has_authz = (
                bool(_IDOR_AUTHZ_CHECK.search(body_text))
                or bool(_MT_SCOPE_TERMS.search(body_text))
            )

            if has_authz:
                line_idx = body_end  # Skip past function
                continue

            # Find the exact query line
            query_line_idx = body_start
            for scan_idx in range(body_start, body_end):
                if _IDOR_DIRECT_QUERY.search(lines[scan_idx].lower()):
                    query_line_idx = scan_idx
                    break

            line_num = query_line_idx + 1
            snip_start = max(0, line_idx - 1)
            snip_end = min(len(lines), query_line_idx + 3)
            snippet = "\n".join(lines[snip_start:snip_end])[:800]

            det_id = hashlib.sha256(
                f"LOGIC-IDOR-001|{fname}|{line_num}".encode()
            ).hexdigest()[:16]

            new_findings.append(EngineFinding(
                rule_id="LOGIC-IDOR-001",
                rule_title=(
                    "Insecure Direct Object Reference — "
                    "Missing Authorization"
                ),
                vulnerability_type="Broken Access Control",
                severity="critical",
                confidence=70.0,
                file_name=fname,
                line=line_num,
                description=(
                    f"Route accepts '{param_name}' parameter and performs "
                    f"direct database lookup at line {line_num} without "
                    f"ownership or tenant validation within "
                    f"{_IDOR_FUNC_BODY_LINES} lines."
                ),
                category="Backend Security",
                owasp="A01:2021 — Broken Access Control",
                cwe="CWE-639",
                matched_pattern=lines[query_line_idx].strip()[:200],
                code_snippet=snippet,
                impact=(
                    "Attacker can access or modify objects belonging "
                    "to other users by manipulating the ID parameter."
                ),
                remediation=(
                    "Validate object ownership or tenant scope before "
                    "returning data. Example: "
                    "if obj.user_id != current_user.id: abort(403)"
                ),
                requires_ai_validation=False,
                severity_weight=11,
                exploitability_score="High",
                detection_id=det_id,
                correlation_flags=["idor_unscoped_access"],
                intelligence_modifiers=["logic_idor_unscoped"],
                vulnerability_family="idor_direct_object_reference",
            ))
            file_count += 1
            line_idx = body_end  # Skip past function body

    return new_findings


# ─── Logic Detector 3: Header-Based Privilege Escalation (LOGIC-PRIV-001) ─


def _detect_header_privilege_trust(
    file_content_lower: Dict[str, str],
    file_lines: Dict[str, List[str]],
) -> List[EngineFinding]:
    """Detect HTTP headers trusted for authorization decisions.

    Strategy (single pass per file, O(n)):
    1. Find lines reading privilege-related HTTP headers
       (X-Is-Admin, X-Role, X-Permissions, etc.)
    2. Check if the value is assigned to a privilege flag variable
       or used in an authorization condition within ±15 lines
    3. If so → emit finding (severity=critical, confidence=80)

    HTTP headers are client-controlled and trivially forgeable.

    CWE-290: Authentication Bypass by Spoofing
    OWASP A01:2021: Broken Access Control
    """
    new_findings: List[EngineFinding] = []

    for fname, content_lower in file_content_lower.items():
        # Quick reject: does this file read privilege-related headers?
        if not (_HEADER_PRIV_READ.search(content_lower)
                or _HEADER_PRIV_BRACKET.search(content_lower)):
            continue

        lines = file_lines.get(fname)
        if not lines:
            continue

        file_count = 0
        for line_idx, line in enumerate(lines):
            if file_count >= _LOGIC_MAX_PER_FILE:
                break

            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith(
                ("#", "//", "*", "/*")
            ):
                continue

            line_lower = line_stripped.lower()

            # Match header read
            header_match = (
                _HEADER_PRIV_READ.search(line_lower)
                or _HEADER_PRIV_BRACKET.search(line_lower)
            )
            if not header_match:
                continue

            header_name = header_match.group(1)

            # Check if used for privilege decisions within scan radius
            scan_start = line_idx
            scan_end = min(
                len(lines), line_idx + _HEADER_PRIV_SCAN_RADIUS + 1
            )
            nearby = "\n".join(lines[scan_start:scan_end]).lower()

            is_priv_assignment = bool(_PRIV_ASSIGNMENT.search(nearby))
            is_priv_condition = bool(_PRIV_CONDITION.search(nearby))

            if not (is_priv_assignment or is_priv_condition):
                continue

            line_num = line_idx + 1
            snip_start = max(0, line_idx - 2)
            snip_end = min(len(lines), line_idx + 5)
            snippet = "\n".join(lines[snip_start:snip_end])[:800]

            det_id = hashlib.sha256(
                f"LOGIC-PRIV-001|{fname}|{line_num}".encode()
            ).hexdigest()[:16]

            new_findings.append(EngineFinding(
                rule_id="LOGIC-PRIV-001",
                rule_title=(
                    "Header-Based Privilege Escalation — "
                    "Forgeable Authorization"
                ),
                vulnerability_type="Broken Access Control",
                severity="critical",
                confidence=80.0,
                file_name=fname,
                line=line_num,
                description=(
                    f"HTTP header '{header_name}' at line {line_num} is "
                    f"used for privilege determination. HTTP headers are "
                    f"client-controlled and trivially forgeable."
                ),
                category="Backend Security",
                owasp="A01:2021 — Broken Access Control",
                cwe="CWE-290",
                matched_pattern=line_stripped[:200],
                code_snippet=snippet,
                impact=(
                    "Complete privilege escalation. Attacker adds a "
                    "forged header (e.g. X-Is-Admin: true) to bypass "
                    "authorization checks entirely."
                ),
                remediation=(
                    "Never trust HTTP headers for authorization. Use "
                    "server-side session state, JWTs with signature "
                    "verification, or middleware-enforced RBAC."
                ),
                requires_ai_validation=False,
                severity_weight=12,
                exploitability_score="High",
                detection_id=det_id,
                correlation_flags=["header_trusted_for_privilege"],
                intelligence_modifiers=["logic_header_privilege_trust"],
                vulnerability_family="header_privilege_escalation",
            ))
            file_count += 1

    return new_findings


# ─── Logic Detector 4: Multi-Tenant List Comprehension (LOGIC-MT-009) ─


def _detect_multitenant_list_comprehension(
    file_content_lower: Dict[str, str],
    file_lines: Dict[str, List[str]],
) -> List[EngineFinding]:
    """Detect multi-tenant leakage via list comprehensions missing tenant filtering.

    Strategy (single scan per file, O(n)):
    1. Skip files without multi-tenant indicators (tenant_id, org_id, etc.)
    2. Pre-split lines once (reuses file_lines index)
    3. Scan for list comprehension pattern [x for x in source if condition]
    4. Check that the condition does NOT reference tenant scope terms
    5. If no scope term → emit finding (severity=high, confidence=65)
    6. Anti-pattern suppression: # nosec, admin_override, system_wide_query
    7. Cap at 3 findings per file

    Example vulnerable pattern:
        related = [d for d in documents_db
                   if any(w in d['title'].lower() for w in words)
                   and d['id'] != doc['id']]

    CWE-284: Improper Access Control
    OWASP A01:2021: Broken Access Control
    """
    new_findings: List[EngineFinding] = []

    for fname, content_lower in file_content_lower.items():
        # 1. Quick reject: file must contain multi-tenant indicator
        has_tenant_context = False
        for indicator in _MT009_TENANT_INDICATORS:
            if indicator in content_lower:
                has_tenant_context = True
                break
        if not has_tenant_context:
            continue

        # 2. Quick reject: file must contain list comprehension syntax
        if " for " not in content_lower or "[" not in content_lower:
            continue

        lines = file_lines.get(fname)
        if not lines:
            continue

        # 3. Anti-pattern file-level check
        suppressed = False
        for ap in _MT009_ANTI_PATTERNS:
            if ap in content_lower:
                suppressed = True
                break
        if suppressed:
            continue

        # 4. Scan for list comprehensions line by line.
        # List comprehensions can span multiple lines, so we build
        # a rolling buffer that tracks bracket depth.
        file_count = 0
        i = 0
        while i < len(lines) and file_count < _MT009_MAX_PER_FILE:
            line = lines[i]
            line_stripped = line.strip()

            # Skip comments and empty lines
            if not line_stripped or line_stripped.startswith(
                ("#", "//", "*", "/*", "'''", '"""')
            ):
                i += 1
                continue

            # Check if this line starts or contains a list comprehension
            line_lower = line_stripped.lower()

            # Fast reject: must have both '[' and 'for' and 'if' at minimum
            if "[" not in line_lower or "for" not in line_lower:
                i += 1
                continue

            # Collect the full expression if it spans multiple lines
            # by tracking bracket depth (max lookahead: 5 lines)
            expr_lines = [line_stripped]
            open_brackets = line_stripped.count("[") - line_stripped.count("]")
            lookahead = 1
            while open_brackets > 0 and lookahead <= 5 and (i + lookahead) < len(lines):
                next_line = lines[i + lookahead].strip()
                expr_lines.append(next_line)
                open_brackets += next_line.count("[") - next_line.count("]")
                lookahead += 1

            full_expr = " ".join(expr_lines).lower()

            # Match list comprehension with conditional
            match = _MT009_LISTCOMP_PATTERN.search(full_expr)
            if not match:
                i += 1
                continue

            condition = match.group(1)

            # 5. Check if condition references any tenant scope term
            has_scope = False
            for term in _MT009_SCOPE_TERMS:
                if term in condition:
                    has_scope = True
                    break

            if has_scope:
                i += 1
                continue

            # 6. Line-level anti-pattern check
            line_suppressed = False
            for ap in _MT009_ANTI_PATTERNS:
                if ap in full_expr:
                    line_suppressed = True
                    break
            if line_suppressed:
                i += 1
                continue

            # Emit finding
            line_num = i + 1
            snip_start = max(0, i - 2)
            snip_end = min(len(lines), i + len(expr_lines) + 2)
            snippet = "\n".join(lines[snip_start:snip_end])[:800]

            det_id = hashlib.sha256(
                f"LOGIC-MT-009|{fname}|{line_num}".encode()
            ).hexdigest()[:16]

            # Confidence: 65, clamped to [0, 100]
            confidence = max(0.0, min(100.0, 65.0))

            new_findings.append(EngineFinding(
                rule_id="LOGIC-MT-009",
                rule_title=(
                    "Multi-Tenant List Comprehension Without Tenant Filter"
                ),
                vulnerability_type="Broken Access Control",
                severity="high",
                confidence=confidence,
                file_name=fname,
                line=line_num,
                description=(
                    f"List comprehension at line {line_num} iterates over "
                    f"a data source with a filter condition that does not "
                    f"reference tenant_id, org_id, or workspace_id. In a "
                    f"multi-tenant context, this may leak cross-tenant data."
                ),
                category="Backend Security",
                owasp="A01:2021 — Broken Access Control",
                cwe="CWE-284",
                matched_pattern=full_expr[:200],
                code_snippet=snippet,
                impact=(
                    "Cross-tenant data leakage. List comprehension returns "
                    "records from all tenants matching the filter condition, "
                    "exposing data belonging to other organizations."
                ),
                remediation=(
                    "Add tenant_id filtering to the list comprehension "
                    "condition. Example: "
                    "[d for d in data if d['tenant_id'] == g.tenant_id "
                    "and <other conditions>]"
                ),
                requires_ai_validation=False,
                severity_weight=9,
                exploitability_score="High",
                detection_id=det_id,
                correlation_flags=["listcomp_missing_tenant_scope"],
                intelligence_modifiers=["logic_mt_isolation_bypass"],
                vulnerability_family="multi_tenant_isolation",
            ))
            file_count += 1

            # Advance past this expression
            i += len(expr_lines)
            continue

        i += 1  # This line only runs if while-condition was False initially

    return new_findings


# ─── Main Entry Point ────────────────────────────────────────────────


def apply_rule_intelligence(
    findings: List[EngineFinding],
    rule_index,
    file_contents: Optional[Dict[str, str]] = None,
) -> List[EngineFinding]:
    """Apply all 7 intelligence capabilities to a list of findings.

    Called AFTER detection and reconstruction, BEFORE deduplication.
    Mutates findings in-place and returns the same list.

    Args:
        findings: List of EngineFinding objects from detection phase.
        rule_index: RuleIndex instance with loaded rules.
        file_contents: Optional dict of {file_name: raw_content} for
            full-file analysis. If None, falls back to snippet-based
            heuristics (lower fidelity but always available).

    Returns:
        The same list of findings, mutated with intelligence metadata.

    Performance: O(n) per finding × 7 capabilities = O(7n) ≈ O(n).
    Correlation index build is O(n) with hash lookups.
    """
    if not findings:
        return findings

    import time
    start = time.monotonic()

    # ── Pre-computation: build indexes ──────────────────────────────
    rule_meta_index = _build_rule_meta_index(rule_index)

    # Group findings by file for correlation analysis
    findings_by_file: Dict[str, List[EngineFinding]] = defaultdict(list)
    for f in findings:
        findings_by_file[f.file_name].append(f)

    # Set of all triggered rule IDs across all files
    all_rule_ids_triggered: Set[str] = {f.rule_id for f in findings}

    # Pre-compute per-file rule_id sets (O(n) build, O(1) lookup)
    # Avoids rebuilding inside _apply_related_rules_correlation
    file_rule_ids_cache: Dict[str, Set[str]] = {
        fname: {f.rule_id for f in flist}
        for fname, flist in findings_by_file.items()
    }

    # Pre-compute per-file layer-1 presence for detection layer scoring.
    # A file "has layer 1" if ANY finding in that file comes from a
    # rule with detection_layer == 1.
    file_has_layer1: Dict[str, bool] = {}
    for fname, flist in findings_by_file.items():
        file_has_layer1[fname] = any(
            rule_meta_index.get(f.rule_id, {}).get("detection_layer", 1) == 1
            for f in flist
        )

    # File content indexes.
    # When file_contents is provided (from pipeline.py scan_jobs),
    # we use the ORIGINAL file content — this is the correct source
    # for line-level anti-pattern checks (not chunked streaming buffer).
    # When not provided (orchestrator path), we fall back to snippet-based
    # approximation with lower fidelity.
    if file_contents:
        file_content_lower = {
            fname: content.lower()
            for fname, content in file_contents.items()
        }
        file_lines = {
            fname: content.split("\n")
            for fname, content in file_contents.items()
        }
    else:
        file_content_lower = _build_file_content_index(findings)
        file_lines = _build_file_lines_index(findings)

    # ── Apply capabilities to each finding ──────────────────────────
    processed = 0
    modifiers_applied = 0

    for finding in findings:
        rule_meta = rule_meta_index.get(finding.rule_id, {})
        content_lower = file_content_lower.get(finding.file_name)
        lines = file_lines.get(finding.file_name)

        # 0. Propagate vulnerability_family from rule to finding
        vf = rule_meta.get("vulnerability_family", "")
        if vf and not finding.vulnerability_family:
            finding.vulnerability_family = vf

        # 1. Detection Layer Activation (with isolation/corroboration scoring)
        _apply_detection_layer(
            finding, rule_meta,
            file_has_layer1=file_has_layer1.get(finding.file_name, False),
        )

        # 2. Attack Surface Amplification
        _apply_attack_surface(finding, rule_meta)

        # 3. Line-Level Anti-Pattern Evaluation (on original file lines)
        _apply_line_level_anti_pattern(
            finding, lines, rule_meta.get("anti_patterns", ())
        )

        # 4. Related Rules Correlation (using pre-built O(1) indexes)
        _apply_related_rules_correlation(
            finding,
            rule_meta.get("related_rules", ()),
            findings_by_file,
            all_rule_ids_triggered,
        )

        # 5. Privilege Context Calibration (conservative amplification)
        _apply_privilege_context(finding, rule_meta)

        # 6. Multi-Function Chain Detection (keyword substring, no re-scan)
        _apply_chain_detection(finding, rule_meta, content_lower)

        # 6b. Taint Path Evidence (keyword presence check, no re-scan)
        _apply_taint_path_evidence(finding, rule_meta, content_lower)

        # 6c. Business Logic Indicators
        _apply_business_logic(finding, rule_meta)

        # 7. Confidence Recalibration (must be last — synthesizes all modifiers)
        # Clamps to [0.0, 100.0]. No negative. No >100.
        # Severity weight boost is dampened when exploitability is already High.
        _recalibrate_confidence(finding)

        processed += 1
        if finding.intelligence_modifiers:
            modifiers_applied += 1

    # ── Logic Detectors: file-level pattern analysis ────────────────
    # These create NEW synthetic findings (not modify existing ones).
    # Run after the main loop so they don't interfere with per-finding
    # capabilities. Synthetic findings have pre-set confidence and
    # do NOT go through _recalibrate_confidence() (confidence is already
    # precisely calibrated at creation time).
    if file_content_lower:
        logic_findings: List[EngineFinding] = []
        logic_findings.extend(
            _detect_multitenant_isolation_bypass(
                file_content_lower, file_lines
            )
        )
        logic_findings.extend(
            _detect_idor_patterns(file_content_lower, file_lines)
        )
        logic_findings.extend(
            _detect_header_privilege_trust(
                file_content_lower, file_lines
            )
        )
        logic_findings.extend(
            _detect_multitenant_list_comprehension(
                file_content_lower, file_lines
            )
        )

        if logic_findings:
            findings.extend(logic_findings)
            processed += len(logic_findings)
            modifiers_applied += sum(
                1 for f in logic_findings if f.intelligence_modifiers
            )
            logger.info(
                "Logic Detectors: emitted %d synthetic findings "
                "(MT-001=%d, IDOR=%d, PRIV=%d, MT-009=%d).",
                len(logic_findings),
                sum(1 for f in logic_findings
                    if f.rule_id == "LOGIC-MT-001"),
                sum(1 for f in logic_findings
                    if f.rule_id == "LOGIC-IDOR-001"),
                sum(1 for f in logic_findings
                    if f.rule_id == "LOGIC-PRIV-001"),
                sum(1 for f in logic_findings
                    if f.rule_id == "LOGIC-MT-009"),
            )

    elapsed_ms = (time.monotonic() - start) * 1000
    logger.info(
        "Rule Intelligence: processed %d findings in %.1f ms "
        "(%d enriched with modifiers).",
        processed,
        elapsed_ms,
        modifiers_applied,
    )

    return findings


# ─── Intelligence Summary (for report aggregation) ───────────────────


def generate_intelligence_summary(
    findings: List[EngineFinding],
) -> Dict:
    """Generate a summary of intelligence layer results for reports.

    Returns a dict suitable for inclusion in ScanReport.
    """
    if not findings:
        return {
            "total_enriched": 0,
            "modifier_distribution": {},
            "correlation_count": 0,
            "exploit_chain_indicators": [],
            "confidence_adjustments": {"boosted": 0, "penalized": 0, "unchanged": 0},
            "logic_detectors": {
                "multitenant_bypass": 0,
                "idor_unscoped": 0,
                "header_privilege_trust": 0,
                "total_synthetic": 0,
            },
        }

    modifier_counter: Dict[str, int] = defaultdict(int)
    correlation_count = 0
    chain_indicators: List[str] = []
    boosted = 0
    penalized = 0
    unchanged = 0

    for f in findings:
        for mod in f.intelligence_modifiers:
            modifier_counter[mod] += 1

        correlation_count += len(f.correlation_flags)

        # Collect chain detection flags
        for flag in f.correlation_flags:
            if flag.startswith("chain_detected:"):
                chain_desc = flag[len("chain_detected:"):]
                if chain_desc not in chain_indicators:
                    chain_indicators.append(chain_desc)

        if f.adjusted_confidence is not None:
            if f.adjusted_confidence > f.confidence:
                boosted += 1
            elif f.adjusted_confidence < f.confidence:
                penalized += 1
            else:
                unchanged += 1
        else:
            unchanged += 1

    return {
        "total_enriched": sum(
            1 for f in findings if f.intelligence_modifiers
        ),
        "modifier_distribution": dict(modifier_counter),
        "correlation_count": correlation_count,
        "exploit_chain_indicators": chain_indicators[:50],  # Cap at 50
        "confidence_adjustments": {
            "boosted": boosted,
            "penalized": penalized,
            "unchanged": unchanged,
        },
        "logic_detectors": {
            "multitenant_bypass": sum(
                1 for f in findings if f.rule_id == "LOGIC-MT-001"
            ),
            "idor_unscoped": sum(
                1 for f in findings if f.rule_id == "LOGIC-IDOR-001"
            ),
            "header_privilege_trust": sum(
                1 for f in findings if f.rule_id == "LOGIC-PRIV-001"
            ),
            "listcomp_tenant_bypass": sum(
                1 for f in findings if f.rule_id == "LOGIC-MT-009"
            ),
            "total_synthetic": sum(
                1 for f in findings if f.rule_id.startswith("LOGIC-")
            ),
        },
    }
