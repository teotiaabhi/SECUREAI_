"""Rule loader for the validation test framework.

Loads YAML rule definitions from disk, compiles regex patterns, and provides
indexed access by id, category, and language through a RuleRegistry.
"""

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Pattern, Set

import yaml

logger = logging.getLogger(__name__)


@dataclass
class RuleDefinition:
    """Parsed representation of a single security rule.

    Attributes:
        rule_id: Unique identifier for the rule (e.g. ``SQL-INJ-001``).
        title: Human-readable rule title.
        language: Programming language the rule targets.
        category: Security category (e.g. ``injection``, ``xss``).
        severity: Severity level: ``critical``, ``high``, ``medium``, ``low``, ``info``.
        confidence: Base confidence score in the range ``[0.0, 1.0]``.
        patterns: Compiled regular expression objects for detection.
        anti_patterns: Literal strings whose presence suppresses a match.
        severity_scoring: Optional dict with additional scoring parameters.
        metadata: Arbitrary key-value metadata from the rule file.
        cross_rule_intelligence: References to related rules or chaining logic.
        regex_compile_time_ms: Time taken to compile all patterns for this rule.
    """

    rule_id: str
    title: str
    language: str
    category: str
    severity: str
    confidence: float
    patterns: List[Pattern[str]]
    anti_patterns: List[str]
    severity_scoring: Dict = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)
    cross_rule_intelligence: Dict = field(default_factory=dict)
    regex_compile_time_ms: float = 0.0


def _determine_flags(flags_spec: Optional[List[str]] = None) -> int:
    """Convert a list of human-readable flag names into combined ``re`` flags.

    Supported names (case-insensitive): ``IGNORECASE``, ``MULTILINE``, ``DOTALL``.

    Args:
        flags_spec: List of flag name strings from the YAML definition.

    Returns:
        Combined integer value of the requested ``re`` flags.
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


def _compile_patterns(
    raw_patterns: List, flags_spec: Optional[List[str]] = None
) -> tuple:
    """Compile a list of raw pattern strings into ``re.Pattern`` objects.

    Args:
        raw_patterns: Regex pattern strings from the YAML file. Each entry may
            be a plain string or a dict with ``pattern`` and ``flags`` keys.
        flags_spec: Default flags to apply when a pattern does not specify its own.

    Returns:
        A tuple of ``(compiled_patterns, compile_time_ms)``.
    """
    compiled: List[Pattern[str]] = []
    start = time.perf_counter()

    default_flags = _determine_flags(flags_spec)

    for entry in raw_patterns:
        if isinstance(entry, dict):
            pattern_str = entry.get("pattern", "")
            per_pattern_flags = _determine_flags(entry.get("flags"))
        else:
            pattern_str = str(entry)
            per_pattern_flags = default_flags

        try:
            compiled.append(re.compile(pattern_str, per_pattern_flags))
        except re.error as exc:
            logger.error("Failed to compile pattern '%s': %s", pattern_str, exc)

    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return compiled, elapsed_ms


def _parse_rule(raw: Dict, source_path: Path) -> Optional[RuleDefinition]:
    """Parse a raw YAML dict into a ``RuleDefinition``.

    Args:
        raw: Dictionary loaded from a YAML rule file.
        source_path: Filesystem path of the source file (used for logging).

    Returns:
        A populated ``RuleDefinition``, or ``None`` if required fields are
        missing or pattern compilation fails completely.
    """
    required_fields = ("rule_id", "title", "language", "category", "severity")
    for fld in required_fields:
        if fld not in raw:
            logger.warning("Rule file %s missing required field '%s'; skipping.", source_path, fld)
            return None

    raw_patterns = raw.get("patterns", [])
    if not raw_patterns:
        logger.warning("Rule %s in %s has no patterns; skipping.", raw["rule_id"], source_path)
        return None

    flags_spec = raw.get("regex_flags")
    compiled, compile_time = _compile_patterns(raw_patterns, flags_spec)

    if not compiled:
        logger.error("All patterns failed to compile for rule %s; skipping.", raw["rule_id"])
        return None

    return RuleDefinition(
        rule_id=raw["rule_id"],
        title=raw["title"],
        language=raw["language"].lower(),
        category=raw["category"].lower(),
        severity=raw.get("severity", "medium").lower(),
        confidence=float(raw.get("confidence", 0.5)),
        patterns=compiled,
        anti_patterns=raw.get("anti_patterns", []),
        severity_scoring=raw.get("severity_scoring", {}),
        metadata=raw.get("metadata", {}),
        cross_rule_intelligence=raw.get("cross_rule_intelligence", {}),
        regex_compile_time_ms=compile_time,
    )


class RuleRegistry:
    """In-memory index of all loaded rule definitions.

    Provides O(1) lookups by rule id and efficient filtering by category
    and language through pre-built indices.
    """

    def __init__(self) -> None:
        self._rules: Dict[str, RuleDefinition] = {}
        self._by_category: Dict[str, List[RuleDefinition]] = {}
        self._by_language: Dict[str, List[RuleDefinition]] = {}
        self.total_compile_time_ms: float = 0.0
        self.load_errors: int = 0

    def register(self, rule: RuleDefinition) -> None:
        """Add a rule to the registry and update indices."""
        self._rules[rule.rule_id] = rule
        self._by_category.setdefault(rule.category, []).append(rule)
        self._by_language.setdefault(rule.language, []).append(rule)
        self.total_compile_time_ms += rule.regex_compile_time_ms

    def get_rule_by_id(self, rule_id: str) -> Optional[RuleDefinition]:
        """Return a single rule by its unique identifier."""
        return self._rules.get(rule_id)

    def get_rules_by_category(self, category: str) -> List[RuleDefinition]:
        """Return all rules belonging to *category* (case-insensitive)."""
        return list(self._by_category.get(category.lower(), []))

    def get_rules_by_language(self, lang: str) -> List[RuleDefinition]:
        """Return all rules targeting *lang* (case-insensitive)."""
        return list(self._by_language.get(lang.lower(), []))

    @property
    def all_rules(self) -> List[RuleDefinition]:
        """Return a list of every registered rule."""
        return list(self._rules.values())

    @property
    def categories(self) -> Set[str]:
        """Return the set of distinct categories present in the registry."""
        return set(self._by_category.keys())

    @property
    def languages(self) -> Set[str]:
        """Return the set of distinct languages present in the registry."""
        return set(self._by_language.keys())

    def __len__(self) -> int:
        return len(self._rules)

    def __repr__(self) -> str:
        return (
            f"<RuleRegistry rules={len(self)} "
            f"categories={len(self._by_category)} "
            f"languages={len(self._by_language)}>"
        )


def load_all_rules(rules_dir: Path) -> RuleRegistry:
    """Discover and load every YAML rule file under *rules_dir*.

    The loader recursively globs for ``**/*.yaml`` and ``**/*.yml`` files,
    parses each one, compiles patterns, and registers valid rules.

    Args:
        rules_dir: Root directory to scan for rule YAML files.

    Returns:
        A populated ``RuleRegistry``.
    """
    registry = RuleRegistry()

    if not rules_dir.is_dir():
        logger.error("Rules directory does not exist: %s", rules_dir)
        return registry

    yaml_files = sorted(rules_dir.glob("**/*.yaml")) + sorted(rules_dir.glob("**/*.yml"))
    logger.info("Found %d YAML rule files in %s", len(yaml_files), rules_dir)

    for yaml_path in yaml_files:
        try:
            with open(yaml_path, "r", encoding="utf-8") as fh:
                documents = list(yaml.safe_load_all(fh))
        except yaml.YAMLError as exc:
            logger.error("Failed to parse %s: %s", yaml_path, exc)
            registry.load_errors += 1
            continue

        for doc in documents:
            if not isinstance(doc, dict):
                continue

            # Handle both top-level rule dicts and files with a `rules:` list wrapper.
            if "rules" in doc and isinstance(doc["rules"], list):
                rule_items = doc["rules"]
            elif "rule_id" in doc:
                rule_items = [doc]
            else:
                logger.debug("Skipping non-rule document in %s", yaml_path)
                registry.load_errors += 1
                continue

            for raw_rule in rule_items:
                if not isinstance(raw_rule, dict):
                    continue
                rule = _parse_rule(raw_rule, yaml_path)
                if rule is not None:
                    if registry.get_rule_by_id(rule.rule_id) is not None:
                        logger.warning("Duplicate rule_id '%s' in %s; overwriting.", rule.rule_id, yaml_path)
                    registry.register(rule)
                else:
                    registry.load_errors += 1

    logger.info(
        "Loaded %d rules (%.1f ms compile time, %d errors).",
        len(registry),
        registry.total_compile_time_ms,
        registry.load_errors,
    )
    return registry
