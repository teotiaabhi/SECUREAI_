"""Rule version comparison module for the validation framework.

Compares rule definitions across two versions (e.g. git branches, tagged
baselines) and produces a structured diff indicating added, removed, and
modified rules including field-level change details.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

logger = logging.getLogger(__name__)


@dataclass
class FieldDiff:
    """A single field-level change within a rule.

    Attributes:
        field_name: Dot-separated path to the changed field.
        old_value: Value in the baseline version (``None`` if field was added).
        new_value: Value in the current version (``None`` if field was removed).
        change_type: One of ``added``, ``removed``, ``modified``.
    """

    field_name: str
    old_value: Any = None
    new_value: Any = None
    change_type: str = "modified"


@dataclass
class RuleDiff:
    """Summary of changes for a single rule between two versions.

    Attributes:
        rule_id: Unique rule identifier.
        status: One of ``added``, ``removed``, ``modified``, ``unchanged``.
        field_diffs: Field-level changes (only populated for ``modified`` rules).
        old_version: Rule version string from the baseline.
        new_version: Rule version string from the current version.
    """

    rule_id: str
    status: str = "unchanged"
    field_diffs: List[FieldDiff] = field(default_factory=list)
    old_version: str = ""
    new_version: str = ""


@dataclass
class VersionCompareResult:
    """Complete comparison result between two rule-set versions.

    Attributes:
        baseline_tag: Label for the baseline version.
        current_tag: Label for the current version.
        added_rules: Rule IDs present only in the current version.
        removed_rules: Rule IDs present only in the baseline.
        modified_rules: Rule IDs with at least one field-level change.
        unchanged_rules: Rule IDs identical in both versions.
        diffs: Per-rule diff objects for all rules.
    """

    baseline_tag: str = ""
    current_tag: str = ""
    added_rules: List[str] = field(default_factory=list)
    removed_rules: List[str] = field(default_factory=list)
    modified_rules: List[str] = field(default_factory=list)
    unchanged_rules: List[str] = field(default_factory=list)
    diffs: List[RuleDiff] = field(default_factory=list)


# -- Tracked fields whose changes are semantically important ----------
_TRACKED_FIELDS = [
    "title",
    "description",
    "severity",
    "confidence",
    "cwe",
    "owasp",
    "patterns",
    "anti_patterns",
    "tags",
    "context_awareness",
    "severity_scoring",
    "exploit_scenario",
    "confidence_factors",
    "remediation",
    "metadata",
    "cross_rule_intelligence",
]


def _flatten_value(value: Any) -> str:
    """Produce a stable, comparable string representation of a value."""
    if isinstance(value, list):
        return str(sorted(str(v) for v in value))
    if isinstance(value, dict):
        return str(sorted((str(k), _flatten_value(v)) for k, v in value.items()))
    return str(value)


def _diff_rule(
    rule_id: str,
    old_rule: Dict[str, Any],
    new_rule: Dict[str, Any],
) -> RuleDiff:
    """Compute field-level diff between two versions of the same rule.

    Args:
        rule_id: The rule being compared.
        old_rule: Baseline rule dictionary.
        new_rule: Current rule dictionary.

    Returns:
        A ``RuleDiff`` with field-level changes.
    """
    field_diffs: List[FieldDiff] = []

    all_keys: Set[str] = set(_TRACKED_FIELDS) & (set(old_rule.keys()) | set(new_rule.keys()))

    for key in sorted(all_keys):
        old_val = old_rule.get(key)
        new_val = new_rule.get(key)

        if old_val is None and new_val is not None:
            field_diffs.append(FieldDiff(field_name=key, new_value=new_val, change_type="added"))
        elif old_val is not None and new_val is None:
            field_diffs.append(FieldDiff(field_name=key, old_value=old_val, change_type="removed"))
        elif _flatten_value(old_val) != _flatten_value(new_val):
            field_diffs.append(
                FieldDiff(field_name=key, old_value=old_val, new_value=new_val, change_type="modified")
            )

    old_version = ""
    new_version = ""
    old_meta = old_rule.get("metadata", {})
    new_meta = new_rule.get("metadata", {})
    if isinstance(old_meta, dict):
        old_version = str(old_meta.get("rule_version", ""))
    if isinstance(new_meta, dict):
        new_version = str(new_meta.get("rule_version", ""))

    status = "modified" if field_diffs else "unchanged"

    return RuleDiff(
        rule_id=rule_id,
        status=status,
        field_diffs=field_diffs,
        old_version=old_version,
        new_version=new_version,
    )


def _load_rules_as_dict(rules_dir: Path) -> Dict[str, Dict[str, Any]]:
    """Load all YAML rule files and return a mapping of rule_id -> raw dict.

    Args:
        rules_dir: Root directory containing YAML rule files.

    Returns:
        Dictionary keyed by ``rule_id``.
    """
    rules: Dict[str, Dict[str, Any]] = {}

    if not rules_dir.is_dir():
        logger.error("Rules directory does not exist: %s", rules_dir)
        return rules

    yaml_files = sorted(rules_dir.glob("**/*.yaml")) + sorted(rules_dir.glob("**/*.yml"))

    for yaml_path in yaml_files:
        try:
            with open(yaml_path, "r", encoding="utf-8") as fh:
                docs = list(yaml.safe_load_all(fh))
        except yaml.YAMLError as exc:
            logger.error("Failed to parse %s: %s", yaml_path, exc)
            continue

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            # Handle files with a top-level "rules" list.
            if "rules" in doc and isinstance(doc["rules"], list):
                for rule_dict in doc["rules"]:
                    if isinstance(rule_dict, dict) and "rule_id" in rule_dict:
                        rules[rule_dict["rule_id"]] = rule_dict
            elif "rule_id" in doc:
                rules[doc["rule_id"]] = doc

    return rules


def compare_versions(
    baseline_dir: Path,
    current_dir: Path,
    baseline_tag: str = "baseline",
    current_tag: str = "current",
) -> VersionCompareResult:
    """Compare two rule-set directories and produce a structured diff.

    Args:
        baseline_dir: Path to the baseline rules directory.
        current_dir: Path to the current rules directory.
        baseline_tag: Human-readable label for the baseline.
        current_tag: Human-readable label for the current version.

    Returns:
        A ``VersionCompareResult`` summarising all changes.
    """
    old_rules = _load_rules_as_dict(baseline_dir)
    new_rules = _load_rules_as_dict(current_dir)

    old_ids = set(old_rules.keys())
    new_ids = set(new_rules.keys())

    result = VersionCompareResult(
        baseline_tag=baseline_tag,
        current_tag=current_tag,
    )

    # Added rules (in current but not baseline)
    for rule_id in sorted(new_ids - old_ids):
        result.added_rules.append(rule_id)
        result.diffs.append(RuleDiff(rule_id=rule_id, status="added"))

    # Removed rules (in baseline but not current)
    for rule_id in sorted(old_ids - new_ids):
        result.removed_rules.append(rule_id)
        result.diffs.append(RuleDiff(rule_id=rule_id, status="removed"))

    # Potentially modified rules (present in both)
    for rule_id in sorted(old_ids & new_ids):
        diff = _diff_rule(rule_id, old_rules[rule_id], new_rules[rule_id])
        result.diffs.append(diff)
        if diff.status == "modified":
            result.modified_rules.append(rule_id)
        else:
            result.unchanged_rules.append(rule_id)

    logger.info(
        "Version comparison: +%d added, -%d removed, ~%d modified, =%d unchanged",
        len(result.added_rules),
        len(result.removed_rules),
        len(result.modified_rules),
        len(result.unchanged_rules),
    )

    return result


def format_comparison_report(result: VersionCompareResult) -> str:
    """Format a ``VersionCompareResult`` as a human-readable Markdown report.

    Args:
        result: The comparison result to format.

    Returns:
        A Markdown string summarising all changes.
    """
    lines: List[str] = []
    lines.append(f"# Rule Version Comparison: {result.baseline_tag} -> {result.current_tag}")
    lines.append("")
    lines.append(f"- **Added:** {len(result.added_rules)}")
    lines.append(f"- **Removed:** {len(result.removed_rules)}")
    lines.append(f"- **Modified:** {len(result.modified_rules)}")
    lines.append(f"- **Unchanged:** {len(result.unchanged_rules)}")
    lines.append("")

    if result.added_rules:
        lines.append("## Added Rules")
        lines.append("")
        for rid in result.added_rules:
            lines.append(f"- `{rid}`")
        lines.append("")

    if result.removed_rules:
        lines.append("## Removed Rules")
        lines.append("")
        for rid in result.removed_rules:
            lines.append(f"- `{rid}`")
        lines.append("")

    if result.modified_rules:
        lines.append("## Modified Rules")
        lines.append("")
        for diff in result.diffs:
            if diff.status != "modified":
                continue
            version_info = ""
            if diff.old_version or diff.new_version:
                version_info = f" ({diff.old_version} -> {diff.new_version})"
            lines.append(f"### `{diff.rule_id}`{version_info}")
            lines.append("")
            lines.append("| Field | Change | Details |")
            lines.append("| ----- | ------ | ------- |")
            for fd in diff.field_diffs:
                detail = ""
                if fd.change_type == "added":
                    detail = "New field added"
                elif fd.change_type == "removed":
                    detail = "Field removed"
                else:
                    detail = "Value changed"
                lines.append(f"| `{fd.field_name}` | {fd.change_type} | {detail} |")
            lines.append("")

    return "\n".join(lines)
