"""
AI Router — Layer 2
Routes code chunks to appropriate AI provider based on complexity.
Includes failover logic between providers.
"""

from typing import Optional, List, Dict
from app.scanner.chunk_engine import CodeChunk
from app.ai.prompt_templates import build_analysis_prompt, build_deep_analysis_prompt
from app.ai.providers import perplexity, phi3, gemma
from app.ai.normalizer import normalize_ai_response
from app.core.logging import get_logger

logger = get_logger("ai_router")

# Complexity classification keywords
COMPLEX_KEYWORDS = {
    "auth", "authentication", "authorization", "jwt", "oauth", "session",
    "payment", "transaction", "crypto", "encrypt", "decrypt", "admin",
    "middleware", "interceptor", "guard", "permission", "role",
}

MEDIUM_KEYWORDS = {
    "database", "query", "api", "route", "controller", "service",
    "upload", "download", "file", "request", "response", "config",
}


def classify_complexity(chunk: CodeChunk) -> str:
    """Classify chunk as simple, medium, or complex."""
    content_lower = chunk.content.lower()
    file_lower = chunk.file_name.lower()

    # Complex: auth, payment, encryption, multi-concern
    if any(kw in content_lower or kw in file_lower for kw in COMPLEX_KEYWORDS):
        return "complex"

    # Long chunks or multi-function chunks
    if chunk.token_estimate > 1500:
        return "complex"

    # Medium: DB, API, file handling
    if any(kw in content_lower or kw in file_lower for kw in MEDIUM_KEYWORDS):
        return "medium"

    if chunk.token_estimate > 500:
        return "medium"

    return "simple"


async def route_chunk(chunk: CodeChunk, depth: str = "standard") -> Optional[dict]:
    """Route a single chunk to the appropriate AI provider."""
    complexity = classify_complexity(chunk)

    if depth == "basic":
        # Basic mode: no AI, rules only
        return None

    # Build the prompt
    if depth == "deep":
        prompt = build_deep_analysis_prompt(chunk.content, chunk.file_name)
    else:
        prompt = build_analysis_prompt(chunk.content, chunk.file_name)

    # Route based on complexity with failover
    result = None

    if complexity == "complex":
        # Try Perplexity → Gemma → Phi-3
        result = await _try_provider(perplexity, prompt, "perplexity")
        if not result:
            result = await _try_provider(gemma, prompt, "gemma")
        if not result:
            result = await _try_provider(phi3, prompt, "phi3")
    elif complexity == "medium":
        # Try Gemma → Phi-3 → Perplexity
        result = await _try_provider(gemma, prompt, "gemma")
        if not result:
            result = await _try_provider(phi3, prompt, "phi3")
        if not result:
            result = await _try_provider(perplexity, prompt, "perplexity")
    else:
        # Simple: Try Phi-3 → Gemma
        result = await _try_provider(phi3, prompt, "phi3")
        if not result:
            result = await _try_provider(gemma, prompt, "gemma")

    if result:
        result = normalize_ai_response(result)

    return result


async def _try_provider(provider, prompt: str, name: str) -> Optional[dict]:
    """Attempt to use a provider, return None on failure."""
    try:
        result = await provider.analyze(prompt)
        if result:
            logger.info("ai_provider_success", provider=name)
        return result
    except Exception as e:
        logger.warning("ai_provider_failed", provider=name, error=str(e))
        return None


async def analyze_chunks(chunks: List[CodeChunk], depth: str = "standard") -> List[Dict]:
    """Run AI analysis on all chunks."""
    results = []
    for chunk in chunks:
        try:
            ai_result = await route_chunk(chunk, depth)
            if ai_result and "vulnerabilities" in ai_result:
                for v in ai_result["vulnerabilities"]:
                    v["file_name"] = chunk.file_name
                    v["source"] = "ai"
                results.append(ai_result)
        except Exception as e:
            logger.error("chunk_ai_error", file=chunk.file_name, error=str(e))

    logger.info("ai_analysis_complete", chunks_analyzed=len(chunks), results=len(results))
    return results
