"""
Confidence Engine
Combines rule engine score and AI confidence with pattern strength
to produce a final confidence value per finding.
"""

from typing import Optional
from app.core.logging import get_logger

logger = get_logger("confidence_engine")


def calculate_final_confidence(
    rule_confidence: float = 0.0,
    ai_confidence: float = 0.0,
    pattern_strength: float = 0.5,
    has_rule_match: bool = False,
    has_ai_match: bool = False,
) -> float:
    """
    Combine rule + AI confidence into a final score.

    Weights:
    - Rule-only: rule_confidence * pattern_strength * 0.7
    - AI-only: ai_confidence * 0.8
    - Both agree: weighted combination boosted
    """
    if has_rule_match and has_ai_match:
        # Both engines found it — high confidence
        combined = (rule_confidence * 0.4 + ai_confidence * 0.6) * pattern_strength
        # Boost for agreement
        agreement_boost = min(10.0, abs(rule_confidence - ai_confidence) * -0.1 + 10)
        final = min(100.0, combined + agreement_boost)
    elif has_rule_match:
        final = rule_confidence * pattern_strength * 0.85
    elif has_ai_match:
        final = ai_confidence * 0.80
    else:
        final = 0.0

    return round(max(0.0, min(100.0, final)), 1)


def merge_rule_and_ai_findings(rule_findings: list, ai_findings: list) -> list:
    """
    Merge rule engine and AI findings, boosting confidence where both agree.
    Returns a unified list of findings.
    """
    merged = []

    # Index AI findings by (file, type-similarity)
    ai_by_file: dict = {}
    for ai_result in ai_findings:
        for v in ai_result.get("vulnerabilities", []):
            fname = v.get("file_name", "")
            ai_by_file.setdefault(fname, []).append(v)

    # Process rule findings, try to match with AI
    seen_keys = set()
    for rf in rule_findings:
        key = (rf.file_name, rf.vulnerability_type, rf.line)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        # Check if AI found something similar
        ai_match = None
        for av in ai_by_file.get(rf.file_name, []):
            if _types_match(rf.vulnerability_type, av.get("type", "")):
                ai_match = av
                break

        ai_conf = float(ai_match.get("confidence", 0)) if ai_match else 0.0

        final_conf = calculate_final_confidence(
            rule_confidence=rf.confidence,
            ai_confidence=ai_conf,
            pattern_strength=0.8,
            has_rule_match=True,
            has_ai_match=ai_match is not None,
        )

        entry = {
            "file_name": rf.file_name,
            "vulnerability_type": rf.vulnerability_type,
            "severity": rf.severity,
            "confidence": final_conf,
            "line_reference": rf.line,
            "impact": ai_match.get("impact", rf.description) if ai_match else rf.description,
            "remediation": ai_match.get("remediation", "") if ai_match else "",
            "exploit_example": ai_match.get("exploit_example", "") if ai_match else "",
            "owasp_mapping": rf.owasp,
            "category": rf.category,
        }
        merged.append(entry)

    # Add AI-only findings not covered by rules
    for ai_result in ai_findings:
        for v in ai_result.get("vulnerabilities", []):
            fname = v.get("file_name", "")
            vtype = v.get("type", "")
            key = (fname, vtype)
            if not any((m["file_name"] == fname and _types_match(m["vulnerability_type"], vtype)) for m in merged):
                final_conf = calculate_final_confidence(
                    ai_confidence=float(v.get("confidence", 50)),
                    has_ai_match=True,
                )
                merged.append({
                    "file_name": fname,
                    "vulnerability_type": vtype,
                    "severity": v.get("severity", "info"),
                    "confidence": final_conf,
                    "line_reference": None,
                    "impact": v.get("impact", ""),
                    "remediation": v.get("remediation", ""),
                    "exploit_example": v.get("exploit_example", ""),
                    "owasp_mapping": v.get("owasp", ""),
                    "category": v.get("category", "Backend Security"),
                })

    logger.info("findings_merged", rule_count=len(rule_findings), ai_count=sum(
        len(r.get("vulnerabilities", [])) for r in ai_findings
    ), merged_count=len(merged))
    return merged


def _types_match(type1: str, type2: str) -> bool:
    """Check if two vulnerability type names refer to the same issue."""
    t1 = type1.lower().replace("-", " ").replace("_", " ")
    t2 = type2.lower().replace("-", " ").replace("_", " ")
    # Exact match or one contains the other
    if t1 == t2:
        return True
    keywords1 = set(t1.split())
    keywords2 = set(t2.split())
    overlap = keywords1 & keywords2
    return len(overlap) >= 2
