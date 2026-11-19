"""
Aggregation Engine
Merges duplicate vulnerabilities, groups by file and type, removes noise.
"""

from typing import List, Dict
from app.scanner.rule_engine import RuleFinding
from app.core.logging import get_logger

logger = get_logger("aggregator")


def deduplicate_findings(findings: List[RuleFinding]) -> List[RuleFinding]:
    """Remove duplicate findings (same rule, file, and line)."""
    seen = set()
    unique = []
    for f in findings:
        key = (f.rule_id, f.file_name, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    removed = len(findings) - len(unique)
    if removed > 0:
        logger.info("duplicates_removed", count=removed)
    return unique


def group_by_file(findings: List[RuleFinding]) -> Dict[str, List[RuleFinding]]:
    """Group findings by file name."""
    groups: Dict[str, List[RuleFinding]] = {}
    for f in findings:
        groups.setdefault(f.file_name, []).append(f)
    return groups


def group_by_type(findings: List[RuleFinding]) -> Dict[str, List[RuleFinding]]:
    """Group findings by vulnerability type."""
    groups: Dict[str, List[RuleFinding]] = {}
    for f in findings:
        groups.setdefault(f.vulnerability_type, []).append(f)
    return groups


def calculate_severity_counts(findings: List[RuleFinding]) -> Dict[str, int]:
    """Count findings by severity level."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.severity.lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def remove_noise(findings: List[RuleFinding], min_confidence: float = 30.0) -> List[RuleFinding]:
    """Remove low-confidence findings considered noise."""
    filtered = [f for f in findings if f.confidence >= min_confidence]
    removed = len(findings) - len(filtered)
    if removed > 0:
        logger.info("noise_removed", count=removed, threshold=min_confidence)
    return filtered


def aggregate_findings(findings: List[RuleFinding]) -> List[RuleFinding]:
    """Full aggregation pipeline: deduplicate → remove noise → sort by severity."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = deduplicate_findings(findings)
    findings = remove_noise(findings)
    findings.sort(key=lambda f: (severity_order.get(f.severity, 5), -f.confidence))
    logger.info("aggregation_complete", total=len(findings))
    return findings
