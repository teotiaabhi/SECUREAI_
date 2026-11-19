"""
AI Provider: Perplexity API (for complex/multi-file analysis)
Uses sonar-pro model with structured JSON output.
"""

import httpx
import json
from typing import Optional
from tenacity import retry, stop_after_attempt, wait_exponential
from app.core.config import get_settings
from app.core.logging import get_logger
from app.ai.prompt_templates import SYSTEM_PROMPT

logger = get_logger("ai_perplexity")


async def analyze(prompt: str) -> Optional[dict]:
    """Send analysis request to Perplexity API via sonar-pro."""
    settings = get_settings()
    timeout = settings.AI_REQUEST_TIMEOUT
    max_attempts = settings.AI_RETRY_ATTEMPTS

    for attempt in range(max_attempts):
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    settings.PPLX_API_URL,
                    json={
                        "model": "sonar-pro",
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.1,
                        "max_tokens": 4096,
                    },
                    headers={
                        "Authorization": f"Bearer {settings.PPLX_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    timeout=timeout,
                )
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]

                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    import re
                    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
                    if match:
                        return json.loads(match.group(1))
                    match = re.search(r"\{.*\}", content, re.DOTALL)
                    if match:
                        return json.loads(match.group())
                    logger.warning("perplexity_json_parse_fail", attempt=attempt)
                    return None
        except httpx.TimeoutException:
            logger.warning("perplexity_timeout", attempt=attempt, timeout=timeout)
            if attempt < max_attempts - 1:
                continue
            return None
        except Exception as e:
            logger.error("perplexity_error", attempt=attempt, error=str(e))
            if attempt < max_attempts - 1:
                continue
            return None
    return None
