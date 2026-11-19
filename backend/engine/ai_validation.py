"""
AI validation trigger — async, non-blocking validation for findings
that have requires_ai_validation=True.

Uses HTTP POST to the configured AI endpoint (PHI3_API_URL by default).
Does not block the main scan pipeline.
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional

import httpx

from engine.models import EngineFinding, MAX_SNIPPET_CHARS

logger = logging.getLogger("engine.ai_validation")

# Defaults (overridden by config if available)
DEFAULT_AI_TIMEOUT = 30
DEFAULT_MAX_CONCURRENT = 5
DEFAULT_MAX_VALIDATIONS = 20

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _build_validation_prompt(finding: EngineFinding) -> str:
    """Build a focused validation prompt for a single finding."""
    snippet = finding.code_snippet[:MAX_SNIPPET_CHARS]
    return (
        f"You are a security code reviewer. Analyze this code for a potential "
        f"{finding.vulnerability_type} vulnerability.\n\n"
        f"File: {finding.file_name}\n"
        f"Line: {finding.line}\n"
        f"Rule: {finding.rule_id} - {finding.rule_title}\n\n"
        f"Code:\n```\n{snippet}\n```\n\n"
        f"Respond with ONLY valid JSON: "
        f'{{"confirmed": true/false, "confidence": 0-100, "reason": "brief explanation"}}'
    )


def _get_ai_config() -> Dict:
    """Get AI configuration. Tries to import from app config, falls back to defaults."""
    try:
        from app.core.config import get_settings

        settings = get_settings()
        return {
            "url": settings.PHI3_API_URL,
            "token": settings.HF_API_TOKEN,
            "timeout": settings.AI_REQUEST_TIMEOUT,
        }
    except Exception:
        return {
            "url": "",
            "token": "",
            "timeout": DEFAULT_AI_TIMEOUT,
        }


async def validate_finding_with_ai(
    finding: EngineFinding,
    ai_config: Dict,
) -> Optional[Dict]:
    """Send a single finding to the AI endpoint for validation.

    Returns {"confirmed": bool, "confidence": int, "reason": str}
    or None on failure/timeout.
    """
    url = ai_config.get("url", "")
    token = ai_config.get("token", "")
    timeout = ai_config.get("timeout", DEFAULT_AI_TIMEOUT)

    if not url or not token:
        return None

    prompt = _build_validation_prompt(finding)

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    payload = {
        "inputs": prompt,
        "parameters": {
            "max_new_tokens": 150,
            "temperature": 0.1,
            "return_full_text": False,
        },
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()

            result = response.json()

            # Parse response — HuggingFace returns [{generated_text: "..."}]
            if isinstance(result, list) and result:
                text = result[0].get("generated_text", "")
            elif isinstance(result, dict):
                text = result.get("generated_text", str(result))
            else:
                text = str(result)

            # Extract JSON from response
            return _parse_ai_response(text)

    except httpx.TimeoutException:
        logger.warning(
            "AI validation timed out for %s in %s",
            finding.rule_id,
            finding.file_name,
        )
        return None
    except Exception as exc:
        logger.warning(
            "AI validation failed for %s: %s", finding.rule_id, exc
        )
        return None


def _parse_ai_response(text: str) -> Optional[Dict]:
    """Extract the JSON verdict from AI response text."""
    # Try direct JSON parse
    text = text.strip()
    try:
        data = json.loads(text)
        if isinstance(data, dict) and "confirmed" in data:
            return {
                "confirmed": bool(data["confirmed"]),
                "confidence": max(0, min(100, int(data.get("confidence", 50)))),
                "reason": str(data.get("reason", ""))[:500],
            }
    except (json.JSONDecodeError, ValueError):
        pass

    # Try to find JSON within markdown code block
    import re

    json_match = re.search(r"\{[^{}]*\"confirmed\"[^{}]*\}", text)
    if json_match:
        try:
            data = json.loads(json_match.group())
            return {
                "confirmed": bool(data["confirmed"]),
                "confidence": max(0, min(100, int(data.get("confidence", 50)))),
                "reason": str(data.get("reason", ""))[:500],
            }
        except (json.JSONDecodeError, ValueError):
            pass

    return None


async def batch_validate_findings(
    findings: List[EngineFinding],
    max_concurrent: int = DEFAULT_MAX_CONCURRENT,
    max_validations: int = DEFAULT_MAX_VALIDATIONS,
) -> List[EngineFinding]:
    """Validate findings that have requires_ai_validation=True.

    Non-blocking: designed to be called with asyncio.create_task().
    Limits concurrent requests and total validations for cost control.

    Confidence adjustments:
    - AI confirms: boost confidence by 10 (capped at 100)
    - AI denies: reduce confidence by 30 (floored at 5)
    - AI timeout/error: leave unchanged
    """
    ai_config = _get_ai_config()
    if not ai_config.get("url") or not ai_config.get("token"):
        logger.info("AI validation skipped: no API URL or token configured.")
        return findings

    # Filter findings requiring validation
    to_validate = [f for f in findings if f.requires_ai_validation]

    if not to_validate:
        return findings

    # Sort by severity (critical first) and take top N
    to_validate.sort(
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 4), -f.confidence)
    )
    to_validate = to_validate[:max_validations]

    logger.info(
        "AI validating %d findings (of %d requiring validation).",
        len(to_validate),
        sum(1 for f in findings if f.requires_ai_validation),
    )

    semaphore = asyncio.Semaphore(max_concurrent)

    async def _validate_with_limit(finding: EngineFinding):
        async with semaphore:
            result = await validate_finding_with_ai(finding, ai_config)

            if result is None:
                return  # Leave unchanged

            finding.ai_validated = True
            finding.ai_confidence = float(result["confidence"])

            if result["confirmed"]:
                finding.confidence = min(100.0, finding.confidence + 10.0)
                logger.debug(
                    "AI confirmed %s in %s (reason: %s)",
                    finding.rule_id,
                    finding.file_name,
                    result["reason"],
                )
            else:
                finding.confidence = max(5.0, finding.confidence - 30.0)
                logger.debug(
                    "AI denied %s in %s (reason: %s)",
                    finding.rule_id,
                    finding.file_name,
                    result["reason"],
                )

    tasks = [_validate_with_limit(f) for f in to_validate]
    await asyncio.gather(*tasks, return_exceptions=True)

    validated_count = sum(1 for f in to_validate if f.ai_validated)
    logger.info("AI validation complete: %d/%d validated.", validated_count, len(to_validate))

    return findings
