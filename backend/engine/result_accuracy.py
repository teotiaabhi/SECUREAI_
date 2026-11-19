"""
Result Accuracy Pipeline — the central orchestrator for noise reduction.

This module ties together all result accuracy improvements:
- Scan scope control (PART 1)
- Rule context gating (PART 2)
- Finding deduplication (PART 3)
- Finding aggregation (PART 4)
- Self-scan protection (PART 5)
- File type filtering (PART 6)
- Result noise reduction / confidence filtering (PART 7)
- Confidence recalibration (PART 8)
- Report integrity protection (PART 9)
- Output improvements (PART 10)

Pipeline position: wraps the entire scan pipeline, invoked from CLI and API
"""

import logging
from typing import Dict, FrozenSet, List, Optional, Tuple

from engine.scan_scope import should_exclude_path, is_report_file
from engine.context_gating import should_rule_execute, is_valid_file_for_language
from engine.finding_aggregation import (
    strict_deduplicate,
    aggregate_findings,
    aggregate_finding_dicts,
)
from engine.models import EngineFinding

logger = logging.getLogger("engine.result_accuracy")

# ─── PART 7: Confidence Thresholds ───────────────────────────────────

CONFIDENCE_THRESHOLDS = {
    "high": 70.0,
    "medium": 40.0,
    "low": 0.0,
}


# ─── PART 8: Confidence Recalibration Rules ──────────────────────────

def recalibrate_confidence(finding: EngineFinding, file_content: str = "") -> float:
    """PART 8: Recalibrate confidence based on detection quality.

    Rules:
    - pattern only (no variable, no user input context) → low confidence
    - pattern + variable name in context → medium confidence
    - pattern + user input indicator → high confidence

    Returns the recalibrated confidence score.
    """
    base_confidence = finding.adjusted_confidence or finding.confidence
    snippet = finding.code_snippet or ""
    matched = finding.matched_pattern or ""

    # Check intelligence modifiers for existing context signals
    modifiers = set(finding.intelligence_modifiers) if finding.intelligence_modifiers else set()

    # Already has input source analysis from confidence_scorer
    has_user_input = any(
        m.startswith("input_source:user_input") for m in modifiers
    )
    has_variable = any(
        m.startswith("input_source:") and "unknown" not in m for m in modifiers
    )
    has_taint = "taint_path_match" in modifiers
    has_dataflow = "dataflow_confirmed" in modifiers

    if has_user_input or has_taint or has_dataflow:
        # Pattern + user input → high confidence (boost)
        return min(100.0, max(base_confidence, 70.0))
    elif has_variable:
        # Pattern + variable context → medium confidence
        return min(100.0, max(base_confidence, 40.0))
    else:
        # Pattern only → cap at low-medium
        # Don't boost, only cap if already higher than warranted
        if base_confidence > 60.0 and not modifiers:
            return base_confidence * 0.7  # Downgrade pattern-only matches
        return base_confidence


def apply_confidence_recalibration(
    findings: List[EngineFinding],
    file_contents: Dict[str, str],
) -> int:
    """PART 8: Apply confidence recalibration to all findings.

    Downgrades pattern-only matches, preserves high-confidence contextual matches.

    Returns count of findings recalibrated.
    """
    recalibrated = 0

    for finding in findings:
        content = file_contents.get(finding.file_name, "")
        old_conf = finding.adjusted_confidence or finding.confidence
        new_conf = recalibrate_confidence(finding, content)

        if abs(new_conf - old_conf) > 0.1:
            finding.adjusted_confidence = round(new_conf, 1)
            if "recalibrated" not in finding.intelligence_modifiers:
                finding.intelligence_modifiers.append("recalibrated")
            recalibrated += 1

    if recalibrated:
        logger.info("Confidence recalibration: adjusted %d findings.", recalibrated)

    return recalibrated


# ─── PART 7: Confidence Filtering ────────────────────────────────────

def filter_by_confidence(
    findings: List[EngineFinding],
    threshold: str = "medium",
    show_low: bool = False,
) -> List[EngineFinding]:
    """PART 7: Filter findings by confidence threshold.

    Default: show only medium/high confidence findings.
    Optional: --show-low-confidence includes all findings.

    Args:
        findings: List of findings to filter.
        threshold: "high", "medium", or "low"
        show_low: If True, include all findings regardless of threshold.

    Returns:
        Filtered list of findings.
    """
    if show_low:
        return findings

    min_confidence = CONFIDENCE_THRESHOLDS.get(threshold.lower(), 40.0)
    result = []

    for finding in findings:
        conf = finding.adjusted_confidence if finding.adjusted_confidence is not None else finding.confidence
        if conf >= min_confidence:
            result.append(finding)

    filtered_out = len(findings) - len(result)
    if filtered_out:
        logger.info(
            "Confidence filter (threshold=%s/%.0f): removed %d low-confidence findings.",
            threshold, min_confidence, filtered_out,
        )

    return result


def filter_dicts_by_confidence(
    findings: List[Dict],
    threshold: str = "medium",
    show_low: bool = False,
) -> List[Dict]:
    """PART 7: Filter finding dicts by confidence threshold (for CLI pipeline)."""
    if show_low:
        return findings

    min_confidence = CONFIDENCE_THRESHOLDS.get(threshold.lower(), 40.0)
    result = []

    for f in findings:
        conf = f.get("adjusted_confidence")
        if conf is None:
            conf = f.get("confidence", 0)
        if conf >= min_confidence:
            result.append(f)

    return result


# ─── Full Pipeline ───────────────────────────────────────────────────

def apply_result_accuracy_pipeline(
    findings: List[EngineFinding],
    file_contents: Dict[str, str],
    confidence_threshold: str = "medium",
    show_low_confidence: bool = False,
) -> List[EngineFinding]:
    """Apply the complete result accuracy pipeline to findings.

    Order:
    1. Strict deduplication (PART 3)
    2. Confidence recalibration (PART 8)
    3. Confidence filtering (PART 7)

    Note: Scan scope (PART 1), context gating (PART 2), file type
    filtering (PART 6), and self-scan protection (PART 5) are applied
    EARLIER in the pipeline (during file discovery and rule selection).

    Aggregation (PART 4) is applied LATER during output formatting.
    """
    original_count = len(findings)

    # PART 3: Strict deduplication
    findings = strict_deduplicate(findings)

    # PART 8: Confidence recalibration
    apply_confidence_recalibration(findings, file_contents)

    # PART 7: Confidence filtering
    findings = filter_by_confidence(findings, confidence_threshold, show_low_confidence)

    final_count = len(findings)
    if original_count != final_count:
        logger.info(
            "Result accuracy pipeline: %d → %d findings (removed %d).",
            original_count, final_count, original_count - final_count,
        )

    return findings
