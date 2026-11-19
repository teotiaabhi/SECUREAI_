"""
Confidence Auto-Calibration — context-aware confidence adjustment.

Runs AFTER clustering, BEFORE deduplication.  Adjusts each finding's
adjusted_confidence based on two independent signal sources:

1. **Context signals** — properties of the finding itself that indicate
   higher or lower reliability (detection_layer, attack_surface_type,
   exploit_chain presence, privilege context).

2. **Corroborating rules** — other findings in the same file within
   a proximity window that reinforce or contradict the finding.

Formula:
    calibrated = base
                 + min(context_signal_sum * 5,  MAX_CONTEXT_BONUS)
                 + min(corroborating_count * 7,  MAX_CORROBORATION_BONUS)
    clamp [MIN_CONFIDENCE, MAX_CONFIDENCE]

Neither source can push confidence above 100 or below 5.

Complexity: O(n log n) per file group (sort by line once, then sliding
window).  Total: O(n log n) across the whole finding set.

No external dependencies.  Deterministic.  No AST.
"""

import logging
from collections import defaultdict
from typing import Dict, List, Set

from engine.models import EngineFinding

logger = logging.getLogger("engine.confidence_calibration")

# ── Tuning constants ────────────────────────────────────────────────

MIN_CONFIDENCE = 5.0
MAX_CONFIDENCE = 100.0

# Context signal bonus per signal (capped at MAX_CONTEXT_BONUS total)
CONTEXT_SIGNAL_VALUE = 5.0
MAX_CONTEXT_BONUS = 15.0

# Per-corroborating-rule bonus (capped at MAX_CORROBORATION_BONUS)
CORROBORATION_VALUE = 7.0
MAX_CORROBORATION_BONUS = 20.0

# Corroboration proximity (lines)
CORROBORATION_PROXIMITY = 40

# ── Context signal evaluation ───────────────────────────────────────

# Intelligence modifiers that indicate deeper / more reliable detection
_DEPTH_MODIFIERS = frozenset({
    "detection_layer_2_corroborated",
    "chain_match",
    "taint_path_match",
    "correlated_rule",
})

# Intelligence modifiers indicating high-exposure attack surface
_EXPOSURE_MODIFIERS = frozenset({
    "attack_surface_api",
    "no_auth_required",
})

# Intelligence modifiers indicating privilege-sensitive context
_PRIVILEGE_MODIFIERS = frozenset({
    "admin_only_risk",
    "privilege_escalation",
    "financial_impact",
    "data_exposure",
    "compliance_relevant",
})


def _count_context_signals(finding: EngineFinding) -> int:
    """Count how many confidence-boosting context signals apply.

    Each signal adds CONTEXT_SIGNAL_VALUE to confidence (up to cap).
    Returns an integer count of active signals (0-4).
    """
    signals = 0
    modifiers = set(finding.intelligence_modifiers) if finding.intelligence_modifiers else set()

    # Signal 1: Detection depth (deeper analysis = more reliable)
    if modifiers & _DEPTH_MODIFIERS:
        signals += 1

    # Signal 2: Attack surface exposure
    if modifiers & _EXPOSURE_MODIFIERS:
        signals += 1

    # Signal 3: Exploit chain membership
    if getattr(finding, "exploit_chain_name", ""):
        signals += 1

    # Signal 4: Privilege / business-impact context
    if modifiers & _PRIVILEGE_MODIFIERS:
        signals += 1

    return signals


# ── Corroboration detection ─────────────────────────────────────────


def _compute_corroboration(
    sorted_findings: List[EngineFinding],
) -> Dict[int, int]:
    """For each finding (by index), count how many *distinct* rule_ids
    appear within ±CORROBORATION_PROXIMITY lines.

    Uses a two-pointer sliding window on a line-sorted list.

    Returns: mapping index → corroborating_rule_count.
    """
    n = len(sorted_findings)
    if n <= 1:
        return {0: 0} if n == 1 else {}

    corroboration: Dict[int, int] = {}
    # Two-pointer: for each i, expand j window
    left = 0
    for i in range(n):
        line_i = sorted_findings[i].line or 0
        rule_i = sorted_findings[i].rule_id

        # Move left pointer forward
        while left < i and (line_i - (sorted_findings[left].line or 0)) > CORROBORATION_PROXIMITY:
            left += 1

        # Count distinct rule_ids in [left..n) within proximity
        distinct_rules: Set[str] = set()
        j = left
        while j < n and ((sorted_findings[j].line or 0) - line_i) <= CORROBORATION_PROXIMITY:
            if j != i and sorted_findings[j].rule_id != rule_i:
                distinct_rules.add(sorted_findings[j].rule_id)
            j += 1

        corroboration[i] = len(distinct_rules)

    return corroboration


# ── Main entry point ────────────────────────────────────────────────


def calibrate_confidence(
    findings: List[EngineFinding],
) -> List[EngineFinding]:
    """Auto-calibrate confidence for all findings in-place.

    Steps:
    1. Group findings by file.
    2. For each file, sort by line, compute corroboration.
    3. For each finding, compute context signals.
    4. Apply combined bonus to adjusted_confidence (or base confidence).
    5. Clamp to [MIN_CONFIDENCE, MAX_CONFIDENCE].

    Returns the same list (mutated in-place) for chaining.
    """
    if not findings:
        return findings

    # Group by file
    by_file: Dict[str, List[EngineFinding]] = defaultdict(list)
    for f in findings:
        by_file[f.file_name].append(f)

    total_adjusted = 0

    for file_name, file_findings in by_file.items():
        # Sort by line for sliding-window corroboration
        file_findings.sort(key=lambda f: f.line or 0)

        # Compute corroboration counts
        corroboration = _compute_corroboration(file_findings)

        for idx, finding in enumerate(file_findings):
            # Base confidence — prefer already-adjusted value if present
            base = (
                finding.adjusted_confidence
                if finding.adjusted_confidence is not None
                else finding.confidence
            )

            # Context signal bonus
            ctx_count = _count_context_signals(finding)
            ctx_bonus = min(ctx_count * CONTEXT_SIGNAL_VALUE, MAX_CONTEXT_BONUS)

            # Corroboration bonus
            corr_count = corroboration.get(idx, 0)
            corr_bonus = min(corr_count * CORROBORATION_VALUE, MAX_CORROBORATION_BONUS)

            total_bonus = ctx_bonus + corr_bonus

            if total_bonus > 0:
                calibrated = max(
                    MIN_CONFIDENCE,
                    min(MAX_CONFIDENCE, base + total_bonus),
                )
                finding.adjusted_confidence = round(calibrated, 1)
                total_adjusted += 1

    if total_adjusted > 0:
        logger.info(
            "Confidence calibration: adjusted %d / %d findings.",
            total_adjusted,
            len(findings),
        )

    return findings
