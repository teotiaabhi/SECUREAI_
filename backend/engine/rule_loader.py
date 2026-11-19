"""
Rule loader — loads YAML security rules, validates schema, groups by language.

Defers regex compilation to worker processes. Stores pattern strings only.
Ported from rule-tests/runner/rule_loader.py with pickle-safe adaptations.
"""

import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml

from engine.models import EngineRule

logger = logging.getLogger("engine.rule_loader")

# ─── Category Mapping ────────────────────────────────────────────────

CATEGORY_MAP: Dict[str, str] = {
    "injection": "Backend Security",
    "auth": "Backend Security",
    "crypto": "Backend Security",
    "rce": "Backend Security",
    "deserialization": "Backend Security",
    "framework_misuse": "Backend Security",
    "path_traversal": "Backend Security",
    "xss": "Frontend Security",
    "ssrf": "API Security",
    "secrets": "Config & Infra",
    "devops": "Config & Infra",
}

REQUIRED_FIELDS = ("rule_id", "title", "language", "category", "severity")


# ─── Flag Handling ────────────────────────────────────────────────────


def _determine_flags(flags_spec: Optional[list] = None) -> int:
    """Convert human-readable flag names to combined re flags.

    Matches rule-tests/runner/rule_loader.py lines 52-78.
    """
    if not flags_spec:
        return re.IGNORECASE | re.MULTILINE

    flag_map = {
        "IGNORECASE": re.IGNORECASE,
        "MULTILINE": re.MULTILINE,
        "DOTALL": re.DOTALL,
    }
    combined = 0
    for name in flags_spec:
        upper = name.upper()
        if upper in flag_map:
            combined |= flag_map[upper]
        else:
            logger.warning("Unknown regex flag '%s'; ignoring.", name)
    return combined


# ─── Pattern Sanitization ────────────────────────────────────────────


def _sanitize_regex_pattern(pattern: str) -> str:
    """Replace unbounded greedy/lazy quantifiers with bounded equivalents.

    Prevents catastrophic backtracking by converting:
      .*   → .{0,500}
      .*?  → .{0,500}?
      .+   → .{1,500}
      .+?  → .{1,500}?

    Only replaces bare dot-star/dot-plus that are NOT already bounded
    (i.e. not followed by {).  Patterns like [^'\"]{0,200} are untouched.
    """
    # Replace .*? (lazy) — must come before .* (greedy)
    pattern = re.sub(r'(?<!\\)\.\*\?(?!\{)', '.{0,500}?', pattern)
    # Replace .* (greedy)
    pattern = re.sub(r'(?<!\\)\.\*(?!\?|\{)', '.{0,500}', pattern)
    # Replace .+? (lazy)
    pattern = re.sub(r'(?<!\\)\.\+\?(?!\{)', '.{1,500}?', pattern)
    # Replace .+ (greedy)
    pattern = re.sub(r'(?<!\\)\.\+(?!\?|\{)', '.{1,500}', pattern)

    # Inside multi-line scanning groups like (?:\s+.{0,500}\n),
    # replace \s+ with [ \t]+ so it only matches horizontal whitespace.
    # \s includes \n which creates ambiguity with the trailing \n in the group,
    # causing catastrophic backtracking on multi-line YAML content.
    pattern = re.sub(
        r'\(\?:\\s\+(\.\{[0-9,]+\}\\n)\)',
        r'(?:[ \\t]+\1)',
        pattern,
    )

    return pattern


# ─── Pattern Extraction ──────────────────────────────────────────────


def _extract_pattern_strings(
    raw_patterns: list, flags_spec: Optional[list] = None
) -> Tuple[Tuple[Tuple[str, int], ...], int]:
    """Extract (pattern_string, flags_int) tuples without compiling.

    Handles both dict format {type: regex, pattern: "..."} and plain strings.
    Returns (tuple_of_pairs, error_count).
    Validates each pattern compiles successfully, but discards the compiled object.
    """
    default_flags = _determine_flags(flags_spec)
    result: List[Tuple[str, int]] = []
    errors = 0

    for entry in raw_patterns:
        if isinstance(entry, dict):
            pattern_str = entry.get("pattern", "")
            per_flags = _determine_flags(entry.get("flags"))
        else:
            pattern_str = str(entry)
            per_flags = default_flags

        if not pattern_str:
            continue

        # Sanitize dangerous patterns to prevent catastrophic backtracking
        pattern_str = _sanitize_regex_pattern(pattern_str)

        # Validate compilability
        try:
            re.compile(pattern_str, per_flags)
            result.append((pattern_str, per_flags))
        except re.error as exc:
            logger.error("Invalid regex pattern '%s': %s", pattern_str[:80], exc)
            errors += 1

    return tuple(result), errors


def _flatten_rule_text(value) -> str:
    """Flatten nested YAML values into a single string for heuristics."""
    if isinstance(value, dict):
        return " ".join(_flatten_rule_text(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(_flatten_rule_text(v) for v in value)
    if value is None:
        return ""
    return str(value)


def _rule_supports_json_files(raw: Dict) -> bool:
    """Return True only for rules that explicitly target JSON files."""
    requires = raw.get("requires", {}) or {}

    file_types = requires.get("file_types") or []
    for file_type in file_types:
        normalized = str(file_type).strip().lower()
        if normalized in {"json", ".json"}:
            return True

    file_paths = requires.get("file_paths") or []
    for file_path in file_paths:
        normalized = str(file_path).strip().lower()
        if normalized.endswith(".json") or ".json" in normalized:
            return True

    rule_text = _flatten_rule_text(
        {
            "title": raw.get("title", ""),
            "description": raw.get("description", ""),
            "impact": raw.get("impact", ""),
            "remediation": raw.get("remediation", ""),
            "references": raw.get("references", []),
            "tags": raw.get("tags", []),
        }
    ).lower()

    strong_file_markers = (
        "package.json",
        "package-lock.json",
        "appsettings.json",
        "tsconfig.json",
        "composer.json",
        "credentials.json",
        "service account json",
        "json file",
        "json key",
    )
    return any(marker in rule_text for marker in strong_file_markers)


# ─── Rule Parsing ────────────────────────────────────────────────────


def _parse_rule(raw: Dict, source_path: Path) -> Optional[EngineRule]:
    """Parse a raw YAML dict into an EngineRule.

    Returns None on validation failure (logs warning).
    """
    for fld in REQUIRED_FIELDS:
        if fld not in raw:
            logger.warning(
                "Rule in %s missing required field '%s'; skipping.", source_path, fld
            )
            return None

    raw_patterns = raw.get("patterns", [])
    if not raw_patterns:
        logger.warning(
            "Rule %s in %s has no patterns; skipping.", raw["rule_id"], source_path
        )
        return None

    flags_spec = raw.get("regex_flags")
    pattern_strings, compile_errors = _extract_pattern_strings(raw_patterns, flags_spec)

    if not pattern_strings:
        logger.error(
            "All patterns failed for rule %s in %s; skipping.",
            raw["rule_id"],
            source_path,
        )
        return None

    # Confidence normalization: accept 0-1 or 0-100 range
    raw_conf = float(raw.get("confidence", 0.5))
    confidence = raw_conf if raw_conf <= 1.0 else raw_conf / 100.0

    # Severity scoring
    sev_scoring = raw.get("severity_scoring", {})
    severity_weight = int(sev_scoring.get("severity_weight", 8))
    exploitability = str(sev_scoring.get("exploitability_score", "Medium"))

    # Cross-rule intelligence
    cross_intel = raw.get("cross_rule_intelligence", {})
    requires_ai = bool(cross_intel.get("requires_ai_validation", False))
    related = cross_intel.get("related_rules", [])
    if isinstance(related, list):
        related_ids = []
        for r in related:
            if isinstance(r, dict):
                related_ids.append(str(r.get("rule_id", "")))
            else:
                related_ids.append(str(r))
        related_tuple = tuple(related_ids)
    else:
        related_tuple = ()

    # Anti-patterns — handle both plain strings and dict-format entries
    raw_anti = raw.get("anti_patterns", [])
    anti_list = []
    for ap in raw_anti:
        if not ap:
            continue
        if isinstance(ap, dict):
            # Extract the pattern string from dict-format anti-patterns
            p = ap.get("pattern", "")
            if p:
                anti_list.append(str(p))
        else:
            anti_list.append(str(ap))
    anti_patterns = tuple(anti_list)

    # Impact and remediation
    impact_raw = raw.get("impact", "")
    if isinstance(impact_raw, dict):
        impact = str(impact_raw.get("description", ""))
    elif isinstance(impact_raw, list):
        impact = "; ".join(str(i) for i in impact_raw)
    else:
        impact = str(impact_raw)

    remediation_raw = raw.get("remediation", "")
    if isinstance(remediation_raw, dict):
        steps = remediation_raw.get("steps", [])
        if steps:
            remediation = "; ".join(str(s) for s in steps)
        else:
            remediation = str(remediation_raw.get("description", ""))
    elif isinstance(remediation_raw, list):
        remediation = "; ".join(str(r) for r in remediation_raw)
    else:
        remediation = str(remediation_raw)

    # Tags
    raw_tags = raw.get("tags", [])
    tags = tuple(str(t) for t in raw_tags) if isinstance(raw_tags, list) else ()

    # Category mapping
    yaml_category = raw["category"].lower()
    db_category = CATEGORY_MAP.get(yaml_category, "Backend Security")

    # ── Rule Intelligence metadata ──────────────────────────────────
    raw_dl = raw.get("detection_layer", 1)
    # Map string layer names to integers
    _layer_map = {
        "direct": 1, "pattern": 1,
        "semantic": 2, "contextual": 2, "behavioral": 2,
        "structural": 2, "dataflow": 2,
        "configuration": 1,
    }
    if isinstance(raw_dl, str):
        detection_layer = _layer_map.get(raw_dl.lower(), 1)
    else:
        try:
            detection_layer = int(raw_dl)
        except (ValueError, TypeError):
            detection_layer = 1
    attack_surface_type = str(raw.get("attack_surface_type", "web")).lower()

    # privilege_context_flags: dict → tuple of (key, value) pairs
    raw_pcf = raw.get("privilege_context_flags", {})
    if isinstance(raw_pcf, dict):
        privilege_context_flags = tuple(sorted(raw_pcf.items()))
    else:
        privilege_context_flags = ()

    # multi_function_chain_patterns: list of strings → tuple
    raw_mfcp = raw.get("multi_function_chain_patterns", [])
    if isinstance(raw_mfcp, list):
        multi_function_chain_patterns = tuple(str(p) for p in raw_mfcp if p)
    else:
        multi_function_chain_patterns = ()

    # probable_taint_paths: list of dicts → tuple of (source, sink, through) tuples
    raw_ptp = raw.get("probable_taint_paths", [])
    probable_taint_paths_list = []
    if isinstance(raw_ptp, list):
        for tp in raw_ptp:
            if isinstance(tp, dict):
                probable_taint_paths_list.append((
                    str(tp.get("source", "")),
                    str(tp.get("sink", "")),
                    str(tp.get("through", "")),
                ))
    probable_taint_paths = tuple(probable_taint_paths_list)

    # business_logic_indicator: dict → tuple of (key, value) pairs
    raw_bli = raw.get("business_logic_indicator", {})
    if isinstance(raw_bli, dict):
        business_logic_indicator = tuple(sorted(raw_bli.items()))
    else:
        business_logic_indicator = ()

    # vulnerability_family: semantic grouping key for dedup
    vulnerability_family = str(raw.get("vulnerability_family", "")).strip()

    # ── Context-aware preconditions ─────────────────────────────────
    from engine.rule_preconditions import parse_preconditions_from_rule_dict
    preconditions = parse_preconditions_from_rule_dict(raw).to_tuple()

    return EngineRule(
        rule_id=raw["rule_id"],
        title=raw["title"],
        description=str(raw.get("description", "")),
        language=raw["language"].lower(),
        category=yaml_category,
        db_category=db_category,
        severity=raw.get("severity", "medium").lower(),
        confidence=confidence,
        cwe=str(raw.get("cwe", "")),
        owasp=str(raw.get("owasp", "")),
        tags=tags,
        pattern_strings=pattern_strings,
        anti_patterns=anti_patterns,
        severity_weight=severity_weight,
        exploitability_score=exploitability,
        requires_ai_validation=requires_ai,
        impact=impact[:2000],
        remediation=remediation[:2000],
        related_rules=related_tuple,
        detection_layer=detection_layer,
        attack_surface_type=attack_surface_type,
        privilege_context_flags=privilege_context_flags,
        multi_function_chain_patterns=multi_function_chain_patterns,
        probable_taint_paths=probable_taint_paths,
        business_logic_indicator=business_logic_indicator,
        vulnerability_family=vulnerability_family,
        preconditions=preconditions,
        supports_json_files=_rule_supports_json_files(raw),
    )


# ─── Rule Index ──────────────────────────────────────────────────────


class RuleIndex:
    """In-memory index of validated rules, grouped by language and category."""

    def __init__(self, rules: List[EngineRule]) -> None:
        self._all: List[EngineRule] = rules
        self._by_language: Dict[str, List[EngineRule]] = {}
        self._by_category: Dict[str, List[EngineRule]] = {}
        self._by_id: Dict[str, EngineRule] = {}
        self._universal: List[EngineRule] = []

        for rule in rules:
            self._by_id[rule.rule_id] = rule
            self._by_language.setdefault(rule.language, []).append(rule)
            self._by_category.setdefault(rule.category, []).append(rule)
            if rule.language in ("all", "universal", "yaml"):
                self._universal.append(rule)

    def rules_for_language(self, lang: str) -> List[EngineRule]:
        """Language-specific rules + universal rules."""
        specific = list(self._by_language.get(lang.lower(), []))
        # Add universal rules (avoid duplicates)
        seen_ids = {r.rule_id for r in specific}
        for r in self._universal:
            if r.rule_id not in seen_ids:
                specific.append(r)
        return specific

    def rules_for_category(self, category: str) -> List[EngineRule]:
        return list(self._by_category.get(category.lower(), []))

    def get_rule(self, rule_id: str) -> Optional[EngineRule]:
        return self._by_id.get(rule_id)

    @property
    def all_rules(self) -> List[EngineRule]:
        return list(self._all)

    @property
    def languages(self) -> Set[str]:
        return set(self._by_language.keys())

    @property
    def categories(self) -> Set[str]:
        return set(self._by_category.keys())

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "total": len(self._all),
            "languages": len(self._by_language),
            "categories": len(self._by_category),
            "universal": len(self._universal),
        }

    def __len__(self) -> int:
        return len(self._all)

    def __repr__(self) -> str:
        return (
            f"<RuleIndex rules={len(self)} "
            f"categories={len(self._by_category)} "
            f"languages={len(self._by_language)}>"
        )


# ─── Loading ─────────────────────────────────────────────────────────


def load_rules(rules_dir: Path) -> RuleIndex:
    """Load all YAML rules from rules_dir, validate, build index.

    Globs for **/*.yaml and **/*.yml.
    """
    if not rules_dir.is_dir():
        logger.error("Rules directory does not exist: %s", rules_dir)
        return RuleIndex([])

    yaml_files = sorted(rules_dir.glob("**/*.yaml")) + sorted(
        rules_dir.glob("**/*.yml")
    )
    logger.info("Found %d YAML rule files in %s", len(yaml_files), rules_dir)

    rules: List[EngineRule] = []
    seen_ids: Set[str] = set()
    load_errors = 0

    for yaml_path in yaml_files:
        try:
            with open(yaml_path, "r", encoding="utf-8") as fh:
                documents = list(yaml.safe_load_all(fh))
        except yaml.YAMLError as exc:
            logger.error("Failed to parse %s: %s", yaml_path, exc)
            load_errors += 1
            continue

        for doc in documents:
            if not isinstance(doc, dict):
                continue

            # Handle {rules: [...]} wrapper or direct rule dicts
            if "rules" in doc and isinstance(doc["rules"], list):
                rule_items = doc["rules"]
            elif "rule_id" in doc:
                rule_items = [doc]
            else:
                continue

            for raw_rule in rule_items:
                if not isinstance(raw_rule, dict):
                    continue

                rule = _parse_rule(raw_rule, yaml_path)
                if rule is not None:
                    if rule.rule_id in seen_ids:
                        logger.warning(
                            "Duplicate rule_id '%s' in %s; overwriting.",
                            rule.rule_id,
                            yaml_path,
                        )
                        # Remove old entry
                        rules = [r for r in rules if r.rule_id != rule.rule_id]
                    seen_ids.add(rule.rule_id)
                    rules.append(rule)
                else:
                    load_errors += 1

    logger.info(
        "Loaded %d rules (%d errors) from %s",
        len(rules),
        load_errors,
        rules_dir,
    )
    return RuleIndex(rules)


@lru_cache(maxsize=1)
def get_rule_index() -> RuleIndex:
    """Cached singleton rule index. Loads from backend/rules/ on first call."""
    rules_dir = Path(__file__).resolve().parent.parent / "rules"
    return load_rules(rules_dir)
