"""
Vulnerability Clustering — reduces noise by grouping multiple findings
that represent the same root vulnerability.

Pipeline position: AFTER Rule Intelligence → BEFORE Deduplication.

Clustering criteria:
    1. Same file_name
    2. Same vulnerability_family (non-empty) OR same CWE
    3. Line proximity ≤ _CLUSTER_PROXIMITY (25 lines)

Output:
    - Cluster representative (highest severity, then highest confidence)
    - evidence_count: how many raw detections formed the cluster
    - clustered_rule_ids: absorbed rule_ids for traceability
    - Preserves merged_rule_ids from earlier semantic merge

Complexity: O(n log n) per-file due to sort; overall O(n log n).

All logic is deterministic. No AI, no AST, no external libraries.
"""

import logging
from collections import defaultdict
from typing import Dict, List, Set, Tuple

from engine.models import EngineFinding

logger = logging.getLogger("engine.clustering")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Maximum line distance for two findings to be clustered together.
_CLUSTER_PROXIMITY = 25

# Maximum cluster size to prevent giant clusters from swallowing
# unrelated findings in extremely dense files.
_MAX_CLUSTER_SIZE = 50

# Files with more findings than this threshold trigger the noise-
# reduction path: confidence is attenuated for lower-severity items
# in high-density files.
_HIGH_DENSITY_THRESHOLD = 30

# Confidence reduction factor applied to non-critical findings in
# high-density files (multiplied by position in density rank).
_DENSITY_CONFIDENCE_PENALTY = 3.0


# ─── Public API ──────────────────────────────────────────────────────


def cluster_findings(findings: List[EngineFinding]) -> List[EngineFinding]:
    """Main entry point: cluster findings by proximity and family.

    Steps:
        1. Partition findings into clusterable (have family or CWE) vs pass-through
        2. Group by (file_name, cluster_key) where cluster_key = family OR CWE
        3. Within each group, sort by line and form proximity clusters
        4. Merge each cluster into a representative finding
        5. Apply noise reduction for high-density files
        6. Return merged list preserving non-clusterable findings

    Returns:
        New list of findings (may be shorter than input).
    """
    if not findings:
        return []

    clusterable: List[EngineFinding] = []
    passthrough: List[EngineFinding] = []

    for f in findings:
        key = _cluster_key(f)
        if key:
            clusterable.append(f)
        else:
            passthrough.append(f)

    if not clusterable:
        return findings  # nothing to cluster

    # Group by (file_name, cluster_key)
    groups: Dict[Tuple[str, str], List[EngineFinding]] = defaultdict(list)
    for f in clusterable:
        gk = (f.file_name, _cluster_key(f))
        groups[gk].append(f)

    clustered_results: List[EngineFinding] = []
    total_absorbed = 0

    for (_fname, _ckey), group in groups.items():
        if len(group) == 1:
            clustered_results.append(group[0])
            continue

        # Sort by line for proximity clustering
        group.sort(key=lambda f: f.line)

        clusters: List[List[EngineFinding]] = []
        current: List[EngineFinding] = [group[0]]

        for f in group[1:]:
            if (
                f.line - current[-1].line <= _CLUSTER_PROXIMITY
                and len(current) < _MAX_CLUSTER_SIZE
            ):
                current.append(f)
            else:
                clusters.append(current)
                current = [f]
        clusters.append(current)

        for cluster in clusters:
            if len(cluster) == 1:
                clustered_results.append(cluster[0])
                continue

            representative = _merge_cluster(cluster)
            clustered_results.append(representative)
            total_absorbed += len(cluster) - 1

    # Combine results
    all_findings = passthrough + clustered_results

    if total_absorbed:
        logger.info(
            "Vulnerability clustering: absorbed %d findings into %d clusters "
            "(%d total output).",
            total_absorbed,
            total_absorbed,  # each absorbed set produced one representative
            len(all_findings),
        )

    # Noise reduction for high-density files
    all_findings = _apply_noise_reduction(all_findings)

    return all_findings


# ─── Internal Helpers ────────────────────────────────────────────────


def _cluster_key(finding: EngineFinding) -> str:
    """Derive a grouping key for clustering.

    Priority: vulnerability_family > CWE > empty (not clusterable).
    """
    if finding.vulnerability_family:
        return f"fam:{finding.vulnerability_family}"
    if finding.cwe:
        return f"cwe:{finding.cwe}"
    return ""


def _merge_cluster(cluster: List[EngineFinding]) -> EngineFinding:
    """Merge a list of nearby findings into a single representative.

    Selection: highest severity, then highest confidence.
    Metadata: union of flags/modifiers, max scores, evidence traceability.
    """
    # Select representative: best severity, then best confidence
    representative = min(
        cluster,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity.lower(), 4),
            -(f.adjusted_confidence if f.adjusted_confidence is not None else f.confidence),
        ),
    )

    # Collect absorbed rule_ids (excluding representative)
    absorbed_ids: List[str] = []
    for f in cluster:
        if f is not representative:
            absorbed_ids.append(f.rule_id)
            # Also carry over any previously merged ids
            absorbed_ids.extend(f.clustered_rule_ids)
            absorbed_ids.extend(f.merged_rule_ids)

    # Merge correlation_flags (deduplicated, order-preserving)
    seen_flags: Set[str] = set(representative.correlation_flags)
    for f in cluster:
        if f is representative:
            continue
        for flag in f.correlation_flags:
            if flag not in seen_flags:
                seen_flags.add(flag)
                representative.correlation_flags.append(flag)

    # Merge intelligence_modifiers (deduplicated)
    seen_mods: Set[str] = set(representative.intelligence_modifiers)
    for f in cluster:
        if f is representative:
            continue
        for mod in f.intelligence_modifiers:
            if mod not in seen_mods:
                seen_mods.add(mod)
                representative.intelligence_modifiers.append(mod)

    # Best adjusted scores
    adj_confs = [
        f.adjusted_confidence for f in cluster
        if f.adjusted_confidence is not None
    ]
    if adj_confs:
        representative.adjusted_confidence = max(adj_confs)

    adj_weights = [
        f.adjusted_severity_weight for f in cluster
        if f.adjusted_severity_weight is not None
    ]
    if adj_weights:
        representative.adjusted_severity_weight = max(adj_weights)

    # Set cluster metadata
    representative.evidence_count = len(cluster)
    representative.clustered_rule_ids = absorbed_ids
    representative.correlation_flags.append(
        f"cluster:evidence={len(cluster)}:"
        f"rules={','.join(absorbed_ids[:10])}"
    )

    return representative


def _apply_noise_reduction(findings: List[EngineFinding]) -> List[EngineFinding]:
    """Reduce confidence for findings in high-density files.

    High-density files (> _HIGH_DENSITY_THRESHOLD findings) often contain
    boilerplate/generated code where many rules fire on similar patterns.
    We attenuate confidence for lower-severity findings proportionally
    to how far above the threshold the file is.

    This does NOT remove findings — it reduces confidence so downstream
    severity normalization may downgrade them and the report ranks them
    lower.

    Complexity: O(n).
    """
    # Count findings per file
    file_counts: Dict[str, int] = defaultdict(int)
    for f in findings:
        file_counts[f.file_name] += 1

    dense_files = {
        fname for fname, count in file_counts.items()
        if count > _HIGH_DENSITY_THRESHOLD
    }

    if not dense_files:
        return findings

    penalized = 0
    for f in findings:
        if f.file_name not in dense_files:
            continue
        # Don't penalize critical findings
        if f.severity.lower() == "critical":
            continue

        excess = file_counts[f.file_name] - _HIGH_DENSITY_THRESHOLD
        penalty = min(excess * _DENSITY_CONFIDENCE_PENALTY, 25.0)

        effective_conf = (
            f.adjusted_confidence if f.adjusted_confidence is not None
            else f.confidence
        )
        new_conf = max(0.0, min(100.0, effective_conf - penalty))
        f.adjusted_confidence = round(new_conf, 1)
        penalized += 1

    if penalized:
        logger.info(
            "Noise reduction: penalized %d findings across %d "
            "high-density file(s) (threshold=%d).",
            penalized,
            len(dense_files),
            _HIGH_DENSITY_THRESHOLD,
        )

    return findings
