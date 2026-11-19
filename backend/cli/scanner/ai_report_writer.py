"""AI-validated report writer for Codex-enhanced scan results.

Writes a JSON report that includes AI validation metadata, removed
false positives summary, and the cleaned set of genuine findings.
"""

import json
import os
import time
from typing import Any, Dict, List

from cli import __version__


def write_ai_report(
    validated_findings: List[Dict],
    removed_findings: List[Dict],
    original_count: int,
    output_path: str,
    scan_target: str,
    files_scanned: int,
    elapsed_sec: float,
    languages: List[str],
    codex_summary: Dict[str, Any] | None = None,
) -> str:
    """Write AI-validated JSON report to disk.

    Args:
        validated_findings: True-positive findings after Codex review.
        removed_findings: Findings removed as false positives with reasons.
        original_count: Total findings before AI validation.
        output_path: Destination file path.
        scan_target: Original scan target path.
        files_scanned: Total files scanned.
        elapsed_sec: Total pipeline duration in seconds.
        languages: Languages detected during scan.
        codex_summary: Optional summary dict from Codex response.

    Returns:
        Absolute path of written report.
    """
    from collections import Counter

    severity_counts = Counter(
        f.get("severity", "info").lower() for f in validated_findings
    )
    total_occurrences = sum(f.get("occurrence_count", 1) for f in validated_findings)

    # Mark each validated finding as AI-validated
    for f in validated_findings:
        f["ai_validated"] = True
        f["ai_validation_engine"] = "openai-codex"

    report: Dict[str, Any] = {
        "version": __version__,
        "tool": "SecureAI Code Analyzer",
        "ai_validation": {
            "engine": "openai-codex",
            "validated": True,
            "original_findings": original_count,
            "true_positives": len(validated_findings),
            "false_positives_removed": len(removed_findings),
            "accuracy_improvement": (
                f"{((len(removed_findings) / original_count) * 100):.1f}%"
                if original_count > 0
                else "0%"
            ),
        },
        "scan": {
            "target": os.path.abspath(scan_target),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "duration_seconds": round(elapsed_sec, 2),
            "files_scanned": files_scanned,
            "languages": sorted(set(languages)),
        },
        "summary": {
            "total_findings": len(validated_findings),
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
            "ai_false_positive_removal": True,
        },
        "findings": validated_findings,
        "removed_false_positives": removed_findings,
    }

    abs_path = os.path.abspath(output_path)
    with open(abs_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, default=str)

    return abs_path
