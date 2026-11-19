"""
Response Normalizer
Validates AI JSON output, standardizes severity, clamps confidence, removes hallucinations.
"""

from typing import Optional, Dict, List, Any
from app.core.logging import get_logger

logger = get_logger("normalizer")

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_CATEGORIES = {
    "Backend Security", "Frontend Security", "API Security",
    "Config & Infra", "Dependency Risk",
}
REQUIRED_VULN_KEYS = {"type", "severity"}
ALLOWED_VULN_KEYS = {
    "type", "severity", "confidence", "line_hint", "impact",
    "remediation", "exploit_example", "owasp", "category",
    "file_name", "source",
}


def normalize_ai_response(response: Any) -> Optional[Dict]:
    """Validate and normalize AI response."""
    if not isinstance(response, dict):
        logger.warning("invalid_response_type", type=type(response).__name__)
        return None

    vulns = response.get("vulnerabilities")
    if not isinstance(vulns, list):
        logger.warning("missing_vulnerabilities_key")
        return {"vulnerabilities": []}

    normalized = []
    for v in vulns:
        if not isinstance(v, dict):
            continue

        # Must have required keys
        if not all(k in v for k in REQUIRED_VULN_KEYS):
            continue

        # Normalize severity
        sev = str(v.get("severity", "")).lower().strip()
        if sev not in VALID_SEVERITIES:
            sev = "info"

        # Clamp confidence
        try:
            conf = float(v.get("confidence", 50))
        except (TypeError, ValueError):
            conf = 50.0
        conf = max(0.0, min(100.0, conf))

        # Normalize category
        cat = v.get("category", "")
        if cat not in VALID_CATEGORIES:
            cat = "Backend Security"

        # Build clean entry — remove any hallucinated keys
        clean = {
            "type": str(v.get("type", "Unknown"))[:255],
            "severity": sev,
            "confidence": conf,
            "line_hint": str(v.get("line_hint", ""))[:100],
            "impact": _sanitize_text(v.get("impact", "")),
            "remediation": _sanitize_text(v.get("remediation", "")),
            "exploit_example": _sanitize_text(v.get("exploit_example", "")),
            "owasp": str(v.get("owasp", ""))[:100],
            "category": cat,
        }

        # Carry over source metadata if present
        if "file_name" in v:
            clean["file_name"] = v["file_name"]
        if "source" in v:
            clean["source"] = v["source"]

        normalized.append(clean)

    logger.debug("response_normalized", input_count=len(vulns), output_count=len(normalized))
    return {"vulnerabilities": normalized}


def _sanitize_text(text: Any) -> str:
    """Sanitize text output, removing potential script injections."""
    if not isinstance(text, str):
        return ""
    # Remove script tags
    import re
    text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)  # Remove all HTML tags
    return text[:2000]  # Limit length
