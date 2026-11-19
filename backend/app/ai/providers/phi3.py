"""
AI Provider: Phi-3 via HuggingFace Inference API (for simple chunks)
"""

import httpx
import json
from typing import Optional
from app.core.config import get_settings
from app.core.logging import get_logger
from app.ai.prompt_templates import SYSTEM_PROMPT

logger = get_logger("ai_phi3")


async def analyze(prompt: str) -> Optional[dict]:
    """Send analysis request to Phi-3 via HuggingFace."""
    settings = get_settings()
    if not settings.HF_API_TOKEN:
        logger.warning("hf_api_token_missing")
        return None

    timeout = settings.AI_REQUEST_TIMEOUT
    max_attempts = settings.AI_RETRY_ATTEMPTS

    for attempt in range(max_attempts):
        try:
            full_prompt = f"{SYSTEM_PROMPT}\n\n{prompt}"
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    settings.PHI3_API_URL,
                    json={
                        "inputs": full_prompt,
                        "parameters": {"max_new_tokens": 2048, "temperature": 0.1, "return_full_text": False},
                    },
                    headers={"Authorization": f"Bearer {settings.HF_API_TOKEN}"},
                    timeout=timeout,
                )
                resp.raise_for_status()
                data = resp.json()
                text = data[0]["generated_text"] if isinstance(data, list) else data.get("generated_text", "")

                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    import re
                    match = re.search(r"\{.*\}", text, re.DOTALL)
                    if match:
                        return json.loads(match.group())
                    logger.warning("phi3_json_parse_fail", attempt=attempt)
                    return None
        except httpx.TimeoutException:
            logger.warning("phi3_timeout", attempt=attempt)
            if attempt < max_attempts - 1:
                continue
            return None
        except Exception as e:
            logger.error("phi3_error", attempt=attempt, error=str(e))
            if attempt < max_attempts - 1:
                continue
            return None
    return None
