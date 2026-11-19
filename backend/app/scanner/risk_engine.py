"""
Risk Engine
Calculates security score, risk grade, and posture summary.
"""

import math
from typing import List, Dict
from app.scanner.rule_engine import RuleFinding
from app.core.logging import get_logger

logger = get_logger("risk_engine")


def calculate_security_score(findings: List[RuleFinding], total_files: int) -> float:
    """
    Score 0–100 based on severity/count relative to codebase size.
    Higher = more secure.

    Uses exponential decay so the score degrades smoothly instead of
    clipping to 0 or 100:

        density  = weighted_penalty / total_files
        score    = 100 × e^(−0.06 × density)

    Reference calibration points (approximate):
        density  0   → 100
        density  2   →  89   (e.g. 1 critical in 8 files)
        density  5   →  74   (e.g. 3 high in 5 files)
        density 10   →  55   (e.g. 1 critical per file)
        density 20   →  30   (heavy finding load)
        density 40   →   9   (extreme)
    """
    if total_files == 0:
        return 100.0

    severity_weights = {"critical": 15, "high": 8, "medium": 3, "low": 1, "info": 0}
    penalty = sum(severity_weights.get(f.severity, 0) for f in findings)

    if penalty == 0:
        return 100.0

    density = penalty / max(total_files, 1)
    score = 100.0 * math.exp(-0.06 * density)

    return round(max(0.0, min(100.0, score)), 1)


def calculate_grade(score: float) -> str:
    """Map score to letter grade."""
    if score >= 90:
        return "A"
    elif score >= 75:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 40:
        return "D"
    else:
        return "F"


def calculate_severity_distribution(findings: List[RuleFinding]) -> Dict[str, int]:
    """Return counts per severity level."""
    dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.severity.lower()
        if sev in dist:
            dist[sev] += 1
    return dist


def generate_posture_summary(score: float, grade: str, dist: Dict[str, int]) -> str:
    """Generate a human-readable risk posture summary."""
    total = sum(dist.values())
    if grade == "A":
        return (
            f"Excellent security posture (Grade {grade}, Score {score}/100). "
            f"{total} total findings detected with no critical issues. "
            "Continue monitoring for regressions."
        )
    elif grade == "B":
        return (
            f"Good security posture (Grade {grade}, Score {score}/100). "
            f"{total} findings detected — {dist['critical']} critical, {dist['high']} high. "
            "Address high-severity items to reach Grade A."
        )
    elif grade == "C":
        return (
            f"Fair security posture (Grade {grade}, Score {score}/100). "
            f"{total} findings detected — {dist['critical']} critical, {dist['high']} high, "
            f"{dist['medium']} medium. Prioritize critical and high items."
        )
    elif grade == "D":
        return (
            f"Poor security posture (Grade {grade}, Score {score}/100). "
            f"{total} findings detected — {dist['critical']} critical, {dist['high']} high. "
            "Immediate action required on critical vulnerabilities."
        )
    else:
        return (
            f"Critical risk level (Grade {grade}, Score {score}/100). "
            f"{total} findings detected — {dist['critical']} critical issues require "
            "immediate remediation to prevent exploitation."
        )


def assess_risk(findings: List[RuleFinding], total_files: int) -> Dict:
    """Full risk assessment pipeline."""
    score = calculate_security_score(findings, total_files)
    grade = calculate_grade(score)
    dist = calculate_severity_distribution(findings)
    summary = generate_posture_summary(score, grade, dist)

    result = {
        "security_score": score,
        "grade": grade,
        "severity_distribution": dist,
        "posture_summary": summary,
        "total_findings": len(findings),
        "total_files": total_files,
    }

    logger.info("risk_assessed", score=score, grade=grade, findings=len(findings))
    return result
