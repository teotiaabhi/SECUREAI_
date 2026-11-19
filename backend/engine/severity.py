"""
Severity normalization and risk scoring.

Computes per-finding risk scores, normalizes severity tiers,
provides category-level aggregation, applies exploit-chain
diminishing return scaling, and calculates repository-level
LOC-based risk density normalization.
"""

import logging
import math
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from engine.models import EngineFinding

logger = logging.getLogger("engine.severity")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

SEVERITY_BASE_WEIGHT = {
    "critical": 15,
    "high": 8,
    "medium": 3,
    "low": 1,
    "info": 0,
}

EXPLOITABILITY_FACTOR = {
    "high": 1.0,
    "medium": 0.7,
    "low": 0.4,
}


def compute_finding_risk_score(finding: EngineFinding) -> float:
    """Compute a per-finding risk score in range [0, 100].

    Formula: severity_weight * (confidence / 100) * exploitability_factor
    Uses the rule's severity_weight if available, otherwise the base weight.

    If the Rule Intelligence layer has provided adjusted_confidence or
    adjusted_severity_weight, those are used in place of the base values.
    The original fields are preserved for audit.
    """
    # Prefer intelligence-adjusted values when present
    weight = (
        finding.adjusted_severity_weight
        if finding.adjusted_severity_weight is not None
        else (finding.severity_weight or SEVERITY_BASE_WEIGHT.get(finding.severity, 3))
    )
    confidence = (
        finding.adjusted_confidence
        if finding.adjusted_confidence is not None
        else finding.confidence
    )
    confidence_ratio = confidence / 100.0
    exploit_key = finding.exploitability_score.lower() if finding.exploitability_score else "medium"
    exploit_factor = EXPLOITABILITY_FACTOR.get(exploit_key, 0.7)

    raw = weight * confidence_ratio * exploit_factor
    # Apply chain risk multiplier (diminishing return for co-occurring families)
    raw *= finding.chain_risk_multiplier
    # Normalize: max possible is 15 * 1.0 * 1.0 = 15 → scale to 0-100
    normalized = min(100.0, (raw / 15.0) * 100.0)
    return round(normalized, 1)


def normalize_severity(
    severity: str,
    risk_score: float,
    requires_ai: bool,
    ai_validated: bool = False,
) -> str:
    """Adjust severity based on risk score and AI validation status.

    Rules:
    - If risk_score < 20 and severity is "high": downgrade to "medium"
    - If requires_ai is True and not validated: cap at "high"
    - Never upgrade severity, only downgrade
    """
    sev = severity.lower()

    if sev == "high" and risk_score < 20.0:
        return "medium"

    if requires_ai and not ai_validated and sev == "critical":
        return "high"

    return sev


def apply_severity_normalization(
    findings: List[EngineFinding],
) -> List[EngineFinding]:
    """Apply risk score computation and severity normalization to all findings.

    Pipeline: exploit-chain scaling → risk score → severity normalization.
    Mutates findings in-place for efficiency. Returns the same list.
    """
    # Phase 1: Exploit-chain diminishing return scaling.
    # When LOGIC-PRIV + LOGIC-IDOR + LOGIC-MT co-occur in the same file,
    # apply multipliers (1.0, 0.7, 0.5) sorted by severity desc so the
    # most critical finding keeps full weight and subsequent families are
    # dampened to prevent score inflation from correlated detections.
    _apply_exploit_chain_scaling(findings)

    # Phase 2: Risk scoring and severity normalization.
    for finding in findings:
        risk = compute_finding_risk_score(finding)

        new_severity = normalize_severity(
            finding.severity,
            risk,
            finding.requires_ai_validation,
            finding.ai_validated,
        )

        if new_severity != finding.severity:
            logger.debug(
                "Severity adjusted for %s: %s → %s (risk_score=%.1f)",
                finding.rule_id,
                finding.severity,
                new_severity,
                risk,
            )
            # EngineFinding is not frozen, so we can mutate
            finding.severity = new_severity

    return findings


# ─── Exploit-Chain Diminishing Return Scaling ────────────────────────

# Families that participate in exploit-chain escalation control.
_CHAIN_FAMILIES = {
    "header_privilege_escalation",
    "idor_direct_object_reference",
    "multi_tenant_isolation",
}

# Diminishing return multipliers applied in severity order.
# First family (highest severity) keeps full weight, subsequent
# families are dampened to prevent score inflation.
_CHAIN_MULTIPLIERS = (1.0, 0.7, 0.5)


def _apply_exploit_chain_scaling(
    findings: List[EngineFinding],
) -> None:
    """Apply diminishing return multipliers when PRIV+IDOR+MT co-occur.

    Only triggers when ALL 3 vulnerability families are present in the
    same file. Findings are grouped by file, then by family. Within each
    file, families are sorted by the maximum severity of their findings
    (critical > high > medium > low > info). The first family keeps
    multiplier 1.0, second gets 0.7, third gets 0.5.

    The multiplier is stored in finding.chain_risk_multiplier and applied
    during compute_finding_risk_score().

    Complexity: O(n) — single pass to group, per-file work is bounded.
    """
    # Group logic findings by file
    file_findings: Dict[str, List[EngineFinding]] = defaultdict(list)
    for f in findings:
        if f.vulnerability_family in _CHAIN_FAMILIES:
            file_findings[f.file_name].append(f)

    if not file_findings:
        return

    chain_files = 0

    for fname, flist in file_findings.items():
        # Group by family
        family_groups: Dict[str, List[EngineFinding]] = defaultdict(list)
        for f in flist:
            family_groups[f.vulnerability_family].append(f)

        # Only apply when ALL 3 families co-occur
        if len(family_groups) < len(_CHAIN_FAMILIES):
            continue
        if not _CHAIN_FAMILIES.issubset(family_groups.keys()):
            continue

        chain_files += 1

        # Sort families by their best (lowest ordinal = most critical) severity
        def _family_sort_key(family_name: str) -> int:
            best = min(
                SEVERITY_ORDER.get(f.severity.lower(), 4)
                for f in family_groups[family_name]
            )
            return best

        sorted_families = sorted(family_groups.keys(), key=_family_sort_key)

        # Apply multipliers
        for idx, family_name in enumerate(sorted_families):
            multiplier = (
                _CHAIN_MULTIPLIERS[idx]
                if idx < len(_CHAIN_MULTIPLIERS)
                else _CHAIN_MULTIPLIERS[-1]
            )
            for f in family_groups[family_name]:
                f.chain_risk_multiplier = multiplier

    if chain_files:
        logger.info(
            "Exploit-chain scaling: applied diminishing return to %d "
            "file(s) with co-occurring PRIV+IDOR+MT families.",
            chain_files,
        )


def compute_severity_distribution(
    findings: List[EngineFinding],
) -> Dict[str, int]:
    """Count findings per severity level."""
    dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = f.severity.lower()
        if key in dist:
            dist[key] += 1
        else:
            dist["info"] += 1
    return dist


def aggregate_by_category(
    findings: List[EngineFinding],
) -> Dict[str, Dict]:
    """Group findings by DB category and compute per-category stats.

    Returns: {
        "Backend Security": {
            "count": N,
            "critical": N,
            "high": N,
            "medium": N,
            "low": N,
            "info": N,
            "avg_confidence": float,
        },
        ...
    }
    """
    groups: Dict[str, List[EngineFinding]] = {}
    for f in findings:
        groups.setdefault(f.category, []).append(f)

    result = {}
    for category, group in groups.items():
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        total_conf = 0.0
        for f in group:
            key = f.severity.lower()
            if key in sev_counts:
                sev_counts[key] += 1
            total_conf += f.confidence

        result[category] = {
            "count": len(group),
            **sev_counts,
            "avg_confidence": round(total_conf / len(group), 1) if group else 0.0,
        }

    return result


def compute_project_risk_classification(
    findings: List[EngineFinding],
    total_files: int,
) -> str:
    """Classify project risk level based on findings distribution.

    Returns: "Low", "Moderate", "High", or "Critical"
    """
    if not findings:
        return "Low"

    dist = compute_severity_distribution(findings)
    critical = dist["critical"]
    high = dist["high"]

    # Critical classification thresholds
    if critical >= 5 or (critical >= 2 and high >= 10):
        return "Critical"
    elif critical >= 1 or high >= 5:
        return "High"
    elif high >= 2 or dist["medium"] >= 10:
        return "Moderate"
    else:
        return "Low"


# ─── Repository-Level Risk Normalization ─────────────────────────────


def compute_repository_loc(
    file_contents: Optional[Dict[str, str]] = None,
) -> int:
    """Count total lines of code across all scanned files.

    Skips blank lines and single-line comments (# prefix) to approximate
    logical LOC. Falls back to 0 if no file contents available.

    Complexity: O(total_lines) — single pass.
    """
    if not file_contents:
        return 0

    loc = 0
    for content in file_contents.values():
        for line in content.split("\n"):
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                loc += 1

    return loc


def compute_risk_density(
    findings: List[EngineFinding],
    loc: int,
) -> float:
    """Calculate weighted risk per LOC.

    Formula: sum(severity_weight × confidence_ratio) / LOC

    Returns 0.0 if LOC is 0.
    """
    if loc <= 0:
        return 0.0

    total_risk = 0.0
    for f in findings:
        weight = (
            f.adjusted_severity_weight
            if f.adjusted_severity_weight is not None
            else (f.severity_weight or SEVERITY_BASE_WEIGHT.get(f.severity, 3))
        )
        confidence = (
            f.adjusted_confidence
            if f.adjusted_confidence is not None
            else f.confidence
        )
        total_risk += weight * (confidence / 100.0)

    return round(total_risk / loc, 6)


def compute_normalized_security_score(
    risk_density: float,
) -> float:
    """Derive security score from risk density using exponential decay.

    Formula: 100 × e^(−4000 × risk_density)

    Calibration:
        density 0.0000 → 100.0  (clean repo)
        density 0.0002 →  44.9  (moderate issues)
        density 0.0005 →  13.5  (significant issues)
        density 0.001  →   1.8  (severe)

    This replaces the naive 100 - penalty model that clips to 0/100.
    """
    score = 100.0 * math.exp(-4000.0 * risk_density)
    return round(max(0.0, min(100.0, score)), 1)


def compute_repository_risk_metrics(
    findings: List[EngineFinding],
    file_contents: Optional[Dict[str, str]] = None,
    total_files: int = 0,
) -> Dict:
    """Compute full repository-level risk metrics.

    Returns dict with:
        repository_loc: int
        risk_density: float
        normalized_security_score: float
        total_files: int
        findings_per_kloc: float
    """
    loc = compute_repository_loc(file_contents)
    density = compute_risk_density(findings, loc)
    score = compute_normalized_security_score(density)

    findings_per_kloc = (
        round(len(findings) / (loc / 1000.0), 2)
        if loc > 0
        else 0.0
    )

    metrics = {
        "repository_loc": loc,
        "risk_density": density,
        "normalized_security_score": score,
        "total_files": total_files,
        "findings_per_kloc": findings_per_kloc,
    }

    logger.info(
        "Repository risk: LOC=%d, density=%.6f, score=%.1f, "
        "findings/kLOC=%.2f",
        loc, density, score, findings_per_kloc,
    )

    return metrics
