"""
Finding Aggregation Engine — groups identical findings into aggregated reports.

Instead of reporting "SQL Injection detected" 3 times, reports:
"SQL Injection detected (3 occurrences)"

PART 3 — Enhanced Finding Deduplication (complements existing dedup)
PART 4 — Finding Aggregation

Pipeline position: AFTER deduplication, BEFORE final output
"""

import logging
from collections import defaultdict
from typing import Dict, List, Set, Tuple

from engine.models import EngineFinding

logger = logging.getLogger("engine.finding_aggregation")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def compute_finding_key(finding: EngineFinding) -> Tuple[str, str, int, str]:
    """Compute a unique key for deduplication.

    PART 3: A finding is unique by (rule_id, file_path, line_number, matched_pattern).
    If a duplicate detection occurs, it must be discarded.
    """
    return (
        finding.rule_id,
        finding.file_name,
        finding.line,
        finding.matched_pattern,
    )


def strict_deduplicate(findings: List[EngineFinding]) -> List[EngineFinding]:
    """PART 3: Strict deduplication by (rule_id, file_path, line_number, matched_pattern).

    Discards exact duplicates, keeping the first occurrence.
    This runs BEFORE aggregation.
    """
    seen: Set[Tuple[str, str, int, str]] = set()
    result: List[EngineFinding] = []

    for finding in findings:
        key = compute_finding_key(finding)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)

    removed = len(findings) - len(result)
    if removed:
        logger.info("Strict dedup: removed %d exact duplicates.", removed)

    return result


def aggregate_findings(findings: List[EngineFinding]) -> List[Dict]:
    """PART 4: Aggregate identical findings into grouped reports.

    Groups findings by (rule_id, file_name) and produces aggregated
    output with occurrence counts.

    Instead of:
        SQL Injection detected
        SQL Injection detected
        SQL Injection detected

    Reports:
        SQL Injection detected (3 occurrences)

    Each aggregated finding includes:
    - occurrence_count: number of times the vulnerability was found
    - affected_lines: list of line numbers where it was detected
    - representative: the highest-severity/confidence finding from the group
    """
    if not findings:
        return []

    # Group by (rule_id, file_name) for aggregation
    groups: Dict[Tuple[str, str], List[EngineFinding]] = defaultdict(list)
    for finding in findings:
        key = (finding.rule_id, finding.file_name)
        groups[key].append(finding)

    aggregated: List[Dict] = []

    for (rule_id, file_name), group in groups.items():
        # Select the representative (best severity, then best confidence)
        representative = min(
            group,
            key=lambda f: (
                SEVERITY_ORDER.get(f.severity, 4),
                -(f.adjusted_confidence if f.adjusted_confidence is not None else f.confidence),
            ),
        )

        # Build aggregated entry
        entry = representative.to_dict()
        entry["occurrence_count"] = len(group)
        entry["affected_lines"] = sorted(set(f.line for f in group))

        if len(group) > 1:
            entry["aggregated"] = True
            entry["aggregated_rule_ids"] = list(set(f.rule_id for f in group))
        else:
            entry["aggregated"] = False

        aggregated.append(entry)

    # Sort by severity, then confidence descending
    aggregated.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f.get("severity", "info"), 4),
            -(f.get("adjusted_confidence") or f.get("confidence", 0)),
        )
    )

    total_findings = len(findings)
    total_aggregated = len(aggregated)
    if total_findings != total_aggregated:
        logger.info(
            "Finding aggregation: %d findings → %d aggregated entries "
            "(reduced by %d).",
            total_findings, total_aggregated,
            total_findings - total_aggregated,
        )

    return aggregated


def format_aggregated_title(finding_dict: Dict) -> str:
    """Format a finding title with occurrence count for display.

    Returns:
        "SQL Injection detected (3 occurrences)" or
        "SQL Injection detected" if only 1 occurrence
    """
    title = finding_dict.get("rule_title", finding_dict.get("vulnerability_type", "Unknown"))
    count = finding_dict.get("occurrence_count", 1)

    if count > 1:
        return f"{title} ({count} occurrences)"
    return title


def aggregate_finding_dicts(findings: List[Dict]) -> List[Dict]:
    """Aggregate raw finding dicts (as produced by workers).

    This version works with dict-format findings (for CLI pipeline).
    Groups by (rule_id, file_name) and adds occurrence_count.
    """
    if not findings:
        return []

    groups: Dict[Tuple[str, str], List[Dict]] = defaultdict(list)
    for finding in findings:
        key = (
            str(finding.get("rule_id", "")),
            str(finding.get("file_name", "")),
        )
        groups[key].append(finding)

    aggregated: List[Dict] = []

    for (rule_id, file_name), group in groups.items():
        # Pick the best representative
        representative = min(
            group,
            key=lambda f: (
                SEVERITY_ORDER.get(str(f.get("severity", "info")).lower(), 4),
                -(f.get("adjusted_confidence") or f.get("confidence", 0)),
            ),
        )

        entry = dict(representative)
        entry["occurrence_count"] = len(group)
        entry["affected_lines"] = sorted(set(
            int(f.get("line", 0) or 0) for f in group
        ))
        entry["aggregated"] = len(group) > 1

        aggregated.append(entry)

    aggregated.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(str(f.get("severity", "info")).lower(), 4),
            -(f.get("adjusted_confidence") or f.get("confidence", 0)),
        )
    )

    return aggregated
