"""
Deduplication layer — prevents duplicate findings and collapses overlapping ranges.

Pipeline: semantic-family merge → exact dedup → overlap collapse → category merge → sort.
"""

import logging
from typing import Dict, List, Set, Tuple

from engine.models import EngineFinding

logger = logging.getLogger("engine.deduplication")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ─── Region proximity for semantic-family grouping ───────────────────
# Findings in the same file, same vulnerability_family, within this many
# lines of each other are considered the same logical vulnerability.
_SEMANTIC_REGION_PROXIMITY = 30


# ─── Semantic Family Merge ───────────────────────────────────────────


def merge_semantic_family(findings: List[EngineFinding]) -> List[EngineFinding]:
    """Merge findings from the same vulnerability_family in the same file
    and root region into a single primary finding.

    This prevents over-counting when e.g. LOGIC-PRIV-001 (header read),
    LOGIC-PRIV-002 (privilege assignment), and LOGIC-PRIV-003 (conditional)
    all fire in the same file region for the same root cause (header trust).

    Grouping criteria:
        1. Same file_name
        2. Same vulnerability_family (non-empty)
        3. Within _SEMANTIC_REGION_PROXIMITY lines of each other

    Merge policy (deterministic):
        - Keep the finding with highest severity, then highest confidence
        - Merge correlation_flags and intelligence_modifiers (deduplicated)
        - Use max(adjusted_confidence) across the group
        - Use max(adjusted_severity_weight) across the group
        - Store consumed rule_ids in merged_rule_ids list
        - Preserve the primary finding's detection_id for traceability

    Findings without a vulnerability_family pass through unchanged.
    """
    if not findings:
        return []

    # Partition: findings WITH a family vs. those WITHOUT
    family_findings: List[EngineFinding] = []
    no_family: List[EngineFinding] = []

    for f in findings:
        if f.vulnerability_family:
            family_findings.append(f)
        else:
            no_family.append(f)

    if not family_findings:
        return findings  # Nothing to merge

    # Group by (file_name, vulnerability_family)
    groups: Dict[Tuple[str, str], List[EngineFinding]] = {}
    for f in family_findings:
        key = (f.file_name, f.vulnerability_family)
        groups.setdefault(key, []).append(f)

    merged_results: List[EngineFinding] = []
    total_merged = 0

    for (fname, family), group in groups.items():
        if len(group) == 1:
            merged_results.append(group[0])
            continue

        # Sort by line number for region clustering
        group.sort(key=lambda f: f.line)

        # Cluster by proximity
        clusters: List[List[EngineFinding]] = []
        current_cluster = [group[0]]

        for f in group[1:]:
            if f.line - current_cluster[0].line <= _SEMANTIC_REGION_PROXIMITY:
                current_cluster.append(f)
            else:
                clusters.append(current_cluster)
                current_cluster = [f]
        clusters.append(current_cluster)

        # Merge each cluster
        for cluster in clusters:
            if len(cluster) == 1:
                merged_results.append(cluster[0])
                continue

            primary = _merge_family_cluster(cluster)
            merged_results.append(primary)
            total_merged += len(cluster) - 1

    if total_merged:
        logger.info(
            "Semantic family merge: absorbed %d findings into %d primaries.",
            total_merged,
            total_merged,  # each absorbed finding had a primary
        )

    return no_family + merged_results


def _merge_family_cluster(cluster: List[EngineFinding]) -> EngineFinding:
    """Merge a cluster of same-family findings into one primary.

    Returns the primary finding (mutated in-place) with merged metadata.
    """
    # Select primary: highest severity, then highest confidence
    primary = min(
        cluster,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 4),
            -(f.adjusted_confidence if f.adjusted_confidence is not None else f.confidence),
        ),
    )

    # Collect all rule_ids from non-primary findings
    consumed_ids = [
        f.rule_id for f in cluster if f is not primary
    ]

    # Merge correlation_flags (deduplicated, order-preserving)
    seen_flags: Set[str] = set(primary.correlation_flags)
    for f in cluster:
        if f is primary:
            continue
        for flag in f.correlation_flags:
            if flag not in seen_flags:
                seen_flags.add(flag)
                primary.correlation_flags.append(flag)

    # Merge intelligence_modifiers (deduplicated, order-preserving)
    seen_mods: Set[str] = set(primary.intelligence_modifiers)
    for f in cluster:
        if f is primary:
            continue
        for mod in f.intelligence_modifiers:
            if mod not in seen_mods:
                seen_mods.add(mod)
                primary.intelligence_modifiers.append(mod)

    # Use best adjusted scores across the cluster
    adj_confs = [
        f.adjusted_confidence for f in cluster
        if f.adjusted_confidence is not None
    ]
    if adj_confs:
        primary.adjusted_confidence = max(adj_confs)

    adj_weights = [
        f.adjusted_severity_weight for f in cluster
        if f.adjusted_severity_weight is not None
    ]
    if adj_weights:
        primary.adjusted_severity_weight = max(adj_weights)

    # Store traceability
    primary.merged_rule_ids = consumed_ids
    primary.vulnerability_family = cluster[0].vulnerability_family

    # Add a correlation flag for downstream audit
    primary.correlation_flags.append(
        f"semantic_merge:family={primary.vulnerability_family}:"
        f"merged={','.join(consumed_ids)}"
    )

    return primary


def deduplicate_exact(findings: List[EngineFinding]) -> List[EngineFinding]:
    """Remove findings with identical (rule_id, file_name, line).

    Keeps the first occurrence (preserves insertion order).
    """
    seen: Set[Tuple[str, str, int]] = set()
    result: List[EngineFinding] = []

    for f in findings:
        key = (f.rule_id, f.file_name, f.line)
        if key not in seen:
            seen.add(key)
            result.append(f)

    removed = len(findings) - len(result)
    if removed:
        logger.info("Exact dedup removed %d duplicate findings.", removed)

    return result


def collapse_overlapping_ranges(
    findings: List[EngineFinding],
    line_proximity: int = 3,
) -> List[EngineFinding]:
    """Collapse findings from the same rule in the same file within
    line_proximity lines of each other.

    For a group of nearby matches from the same rule:
    - Keep the one with the lowest line number
    - Use the highest confidence from the group
    """
    if not findings:
        return []

    # Group by (rule_id, file_name)
    groups: Dict[Tuple[str, str], List[EngineFinding]] = {}
    for f in findings:
        key = (f.rule_id, f.file_name)
        groups.setdefault(key, []).append(f)

    result: List[EngineFinding] = []
    collapsed_count = 0

    for key, group in groups.items():
        if len(group) == 1:
            result.append(group[0])
            continue

        # Sort by line number
        group.sort(key=lambda f: f.line)

        # Merge consecutive entries within proximity
        current_cluster = [group[0]]

        for f in group[1:]:
            if f.line - current_cluster[-1].line <= line_proximity:
                current_cluster.append(f)
            else:
                # Emit the best from current cluster
                result.append(_best_from_cluster(current_cluster))
                collapsed_count += len(current_cluster) - 1
                current_cluster = [f]

        # Emit final cluster
        result.append(_best_from_cluster(current_cluster))
        collapsed_count += len(current_cluster) - 1

    if collapsed_count:
        logger.info(
            "Overlap collapse merged %d findings into existing entries.",
            collapsed_count,
        )

    return result


def merge_category_hits(
    findings: List[EngineFinding],
    line_proximity: int = 5,
) -> List[EngineFinding]:
    """Merge findings from related rules (same CWE) hitting the same
    file within a proximity window into a single finding.

    This handles cases where e.g. INJ-PY-006 (pickle deser in injection/)
    and DESER-PY-001 (pickle deser in deserialization/) both fire on
    the same or adjacent lines.

    Enhanced: uses ±line_proximity instead of exact-line matching.
    """
    if not findings:
        return []

    # Group by (file_name, cwe) — only for findings with a CWE
    cwe_groups: Dict[Tuple[str, str], List[EngineFinding]] = {}
    no_cwe: List[EngineFinding] = []

    for f in findings:
        if f.cwe:
            key = (f.file_name, f.cwe)
            cwe_groups.setdefault(key, []).append(f)
        else:
            no_cwe.append(f)

    result: List[EngineFinding] = list(no_cwe)
    merged_count = 0

    for (fname, cwe), group in cwe_groups.items():
        if len(group) == 1:
            result.append(group[0])
            continue

        # Sort by line for proximity clustering
        group.sort(key=lambda f: f.line)

        # Cluster by line proximity
        clusters: List[List[EngineFinding]] = []
        current_cluster = [group[0]]

        for f in group[1:]:
            if f.line - current_cluster[-1].line <= line_proximity:
                current_cluster.append(f)
            else:
                clusters.append(current_cluster)
                current_cluster = [f]
        clusters.append(current_cluster)

        # Merge each cluster — keep the best finding
        for cluster in clusters:
            if len(cluster) == 1:
                result.append(cluster[0])
            else:
                best = _best_from_cluster(cluster)
                # Track which rules were merged
                consumed = [f.rule_id for f in cluster if f is not best]
                if consumed:
                    best.merged_rule_ids = list(
                        set(best.merged_rule_ids + consumed)
                    )
                    best.evidence_count = max(best.evidence_count, len(cluster))
                result.append(best)
                merged_count += len(cluster) - 1

    if merged_count:
        logger.info(
            "Category merge (±%d lines) combined %d related findings.",
            line_proximity, merged_count,
        )

    return result


def deduplicate_findings(findings: List[EngineFinding]) -> List[EngineFinding]:
    """Full dedup pipeline: semantic-family → exact → overlap → category merge.

    Returns deduplicated list sorted by severity (critical first),
    then confidence (highest first).
    """
    original_count = len(findings)

    step0 = merge_semantic_family(findings)
    step1 = deduplicate_exact(step0)
    step2 = collapse_overlapping_ranges(step1)
    step3 = merge_category_hits(step2)

    # Sort: severity priority, then confidence descending
    step3.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 4),
            -f.confidence,
        )
    )

    final_count = len(step3)
    if original_count != final_count:
        logger.info(
            "Dedup pipeline: %d → %d findings (removed %d).",
            original_count,
            final_count,
            original_count - final_count,
        )

    return step3


# ─── Helpers ─────────────────────────────────────────────────────────


def _best_from_cluster(cluster: List[EngineFinding]) -> EngineFinding:
    """Select the best finding from a cluster of related matches.

    Priority: highest severity, then highest confidence.
    Return the winner (not a new object — preserves all original fields).
    """
    return min(
        cluster,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 4),
            -f.confidence,
        ),
    )
