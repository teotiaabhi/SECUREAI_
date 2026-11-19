"""JSON report writer for scan results."""

import json
import os
import time
from typing import Any, Dict, List

from cli import __version__


def write_report(
    findings: List[Dict],
    output_path: str,
    scan_target: str,
    files_scanned: int,
    elapsed_sec: float,
    languages: List[str],
) -> str:
    """Write JSON report to disk.

    Args:
        findings: List of finding dicts (aggregated, from finding_aggregation).
        output_path: Destination file path.
        scan_target: Original scan target path.
        files_scanned: Total files scanned.
        elapsed_sec: Scan duration in seconds.
        languages: Languages detected during scan.

    Returns:
        Absolute path of written report.
    """
    from collections import Counter

    severity_counts = Counter(f.get("severity", "info").lower() for f in findings)

    # Count total occurrences (includes aggregated counts)
    total_occurrences = sum(f.get("occurrence_count", 1) for f in findings)

    report: Dict[str, Any] = {
        "version": __version__,
        "tool": "SecureAI Code Analyzer",
        "scan": {
            "target": os.path.abspath(scan_target),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "duration_seconds": round(elapsed_sec, 2),
            "files_scanned": files_scanned,
            "languages": sorted(set(languages)),
        },
        "summary": {
            "total_findings": len(findings),
            "total_occurrences": total_occurrences,
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "info": severity_counts.get("info", 0),
        },
        "pipeline": {
            "scan_scope_control": True,
            "context_gating": True,
            "deduplication": True,
            "aggregation": True,
            "self_scan_protection": True,
            "file_type_filtering": True,
            "confidence_filtering": True,
            "confidence_recalibration": True,
        },
        "findings": findings,
    }

    abs_path = os.path.abspath(output_path)
    with open(abs_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, default=str)

    return abs_path
