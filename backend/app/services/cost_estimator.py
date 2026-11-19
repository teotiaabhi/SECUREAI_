"""
Scan cost estimator — pre-scan budget check and token estimation.

Estimates AI token usage before execution so the frontend can display
cost expectations and the backend can enforce daily budgets per tier.
"""

from typing import Dict, List, Optional

from fastapi import HTTPException

from app.middleware.tier_limits import get_ai_tokens_per_day


# ── Language complexity weights ──────────────────────────────
# Higher weights = more complex ASTs / deeper AI analysis needed.
LANGUAGE_WEIGHTS: Dict[str, float] = {
    "python": 1.0,
    "javascript": 1.0,
    "typescript": 1.1,
    "jsx": 1.1,
    "tsx": 1.1,
    "java": 1.2,
    "kotlin": 1.2,
    "csharp": 1.2,
    "go": 1.0,
    "rust": 1.5,
    "cpp": 1.5,
    "c": 1.3,
    "php": 1.0,
    "ruby": 1.0,
    "swift": 1.2,
    "scala": 1.3,
    "sql": 0.8,
    "shell": 0.6,
    "yaml": 0.4,
    "json": 0.3,
    "html": 0.5,
    "css": 0.3,
}

# Base tokens per file (overhead for prompt framing, rule matching, etc.)
BASE_TOKENS_PER_FILE = 150

# Bytes-to-token ratio (rough: ~4 chars per token on average)
BYTES_PER_TOKEN = 4

# Scan mode multipliers
MODE_MULTIPLIERS: Dict[str, float] = {
    "full": 1.0,
    "diff": 0.4,     # only changed files
    "quick": 0.3,    # shallow analysis
}

# Duration estimate constants (seconds)
DURATION_PER_FILE_BASE = 0.5       # base time per file
DURATION_PER_1K_TOKENS = 0.8      # AI inference overhead per 1K tokens


def estimate_scan_cost(
    file_count: int,
    total_size_bytes: int,
    languages: Optional[List[str]] = None,
    scan_mode: str = "full",
    tier: str = "free",
    ai_tokens_already_used: int = 0,
) -> Dict:
    """Estimate AI token usage and scan duration before execution.

    Args:
        file_count: Number of files to scan.
        total_size_bytes: Total source code size in bytes.
        languages: List of detected languages (for weighting).
        scan_mode: "full", "diff", or "quick".
        tier: User tier for budget lookup.
        ai_tokens_already_used: Tokens consumed today so far.

    Returns:
        {
            "estimated_tokens": int,
            "estimated_duration_seconds": float,
            "within_budget": bool,
            "daily_budget": int,
            "remaining_budget": int,
        }
    """
    # Compute language weight average
    if languages:
        weights = [LANGUAGE_WEIGHTS.get(lang.lower(), 1.0) for lang in languages]
        avg_weight = sum(weights) / len(weights) if weights else 1.0
    else:
        avg_weight = 1.0

    # Token estimate = (file overhead + content tokens) * language weight * mode multiplier
    content_tokens = total_size_bytes / BYTES_PER_TOKEN
    raw_tokens = (file_count * BASE_TOKENS_PER_FILE) + content_tokens
    mode_mult = MODE_MULTIPLIERS.get(scan_mode, 1.0)
    estimated_tokens = int(raw_tokens * avg_weight * mode_mult)

    # Duration estimate
    estimated_duration = (
        file_count * DURATION_PER_FILE_BASE
        + (estimated_tokens / 1000) * DURATION_PER_1K_TOKENS
    )

    # Budget check
    daily_budget = get_ai_tokens_per_day(tier)
    remaining = max(0, daily_budget - ai_tokens_already_used)
    within_budget = estimated_tokens <= remaining

    return {
        "estimated_tokens": estimated_tokens,
        "estimated_duration_seconds": round(estimated_duration, 1),
        "within_budget": within_budget,
        "daily_budget": daily_budget,
        "remaining_budget": remaining,
    }


def check_budget_before_scan(
    user,
    estimated_tokens: int,
) -> None:
    """Raise 402 if user would exceed daily AI token budget.

    Args:
        user: User ORM instance (needs tier, ai_tokens_used).
        estimated_tokens: Estimated tokens for the upcoming scan.

    Raises:
        HTTPException(402) if budget would be exceeded.
    """
    tier = getattr(user, "tier", "free")
    if hasattr(tier, "value"):
        tier = tier.value

    daily_budget = get_ai_tokens_per_day(tier)
    used = getattr(user, "ai_tokens_used", 0) or 0
    remaining = max(0, daily_budget - used)

    if estimated_tokens > remaining:
        raise HTTPException(
            status_code=402,
            detail=(
                f"Estimated token usage ({estimated_tokens:,}) exceeds your "
                f"remaining daily budget ({remaining:,} of {daily_budget:,}). "
                f"Upgrade your plan for higher limits."
            ),
        )
