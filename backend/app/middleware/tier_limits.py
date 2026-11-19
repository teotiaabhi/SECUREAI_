"""
Tier-based resource limits — enforces daily scan quotas and
per-tier file/repo size limits.

Tiers: free, pro, enterprise.
Limits are checked and counters incremented atomically per request.
"""

import logging
from datetime import date
from typing import Dict, Any

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("middleware.tier_limits")

TIER_LIMITS: Dict[str, Dict[str, Any]] = {
    "free": {
        "scans_per_day": 50,
        "max_repo_size_mb": 50,
        "max_files": 100,
        "ai_tokens_per_day": 250_000,
        "storage_cap_bytes": 500 * 1024 * 1024,           # 500 MB
    },
    "pro": {
        "scans_per_day": 200,
        "max_repo_size_mb": 500,
        "max_files": 2_000,
        "ai_tokens_per_day": 1_000_000,
        "storage_cap_bytes": 5 * 1024 * 1024 * 1024,       # 5 GB
    },
    "enterprise": {
        "scans_per_day": 1_000,
        "max_repo_size_mb": 2_000,
        "max_files": 10_000,
        "ai_tokens_per_day": 5_000_000,
        "storage_cap_bytes": 50 * 1024 * 1024 * 1024,      # 50 GB
    },
}


def _get_tier_limits(tier: str) -> Dict[str, Any]:
    """Get limits for a tier, defaulting to free."""
    return TIER_LIMITS.get(tier, TIER_LIMITS["free"])


async def enforce_scan_limits(user, db: AsyncSession) -> None:
    """Check and increment daily scan counter. Raises 429 on limit.

    Args:
        user: User ORM instance (must have tier, scans_today, last_scan_reset).
        db: Active database session.
    """
    tier = getattr(user, "tier", "free")
    if hasattr(tier, "value"):
        tier = tier.value
    limits = _get_tier_limits(tier)
    max_scans = limits["scans_per_day"]

    today = date.today()

    # Reset daily counters if new day
    if user.last_scan_reset is None or user.last_scan_reset < today:
        user.scans_today = 0
        user.ai_tokens_used = 0
        user.last_scan_reset = today

    if user.scans_today >= max_scans:
        logger.warning(
            "scan_limit_exceeded user=%s tier=%s scans=%d limit=%d",
            user.id, tier, user.scans_today, max_scans,
        )
        raise HTTPException(
            status_code=429,
            detail=f"Daily scan limit reached ({max_scans} scans/day for {tier} tier). "
                   "Upgrade your plan for higher limits.",
        )

    user.scans_today += 1
    await db.flush()


def get_max_files(tier: str) -> int:
    """Get max files per scan for a tier."""
    return _get_tier_limits(tier)["max_files"]


def get_max_repo_size_mb(tier: str) -> int:
    """Get max repository size in MB for a tier."""
    return _get_tier_limits(tier)["max_repo_size_mb"]


def get_ai_tokens_per_day(tier: str) -> int:
    """Get daily AI token budget for a tier."""
    return _get_tier_limits(tier)["ai_tokens_per_day"]


def get_storage_cap_bytes(tier: str) -> int:
    """Get storage cap in bytes for a tier."""
    return _get_tier_limits(tier).get("storage_cap_bytes", 500 * 1024 * 1024)


async def enforce_ai_token_limits(
    user, estimated_tokens: int, db: AsyncSession
) -> None:
    """Check if estimated tokens fit within the user's daily AI budget.

    Raises 402 if budget would be exceeded.

    Args:
        user: User ORM instance.
        estimated_tokens: Estimated token consumption for the scan.
        db: Active database session (for daily reset if needed).
    """
    tier = getattr(user, "tier", "free")
    if hasattr(tier, "value"):
        tier = tier.value

    budget = get_ai_tokens_per_day(tier)
    used = getattr(user, "ai_tokens_used", 0) or 0
    remaining = max(0, budget - used)

    if estimated_tokens > remaining:
        logger.warning(
            "ai_token_limit_exceeded user=%s tier=%s used=%d estimated=%d budget=%d",
            user.id, tier, used, estimated_tokens, budget,
        )
        raise HTTPException(
            status_code=402,
            detail=(
                f"Estimated AI token usage ({estimated_tokens:,}) exceeds your "
                f"remaining daily budget ({remaining:,} of {budget:,}). "
                f"Upgrade your plan for higher limits."
            ),
        )


async def enforce_storage_limits(
    user, estimated_size_bytes: int, db: AsyncSession
) -> None:
    """Check if adding estimated_size_bytes would exceed the tier storage cap.

    Raises 402 if storage cap would be exceeded.

    Args:
        user: User ORM instance.
        estimated_size_bytes: Size of incoming data in bytes.
        db: Active database session.
    """
    tier = getattr(user, "tier", "free")
    if hasattr(tier, "value"):
        tier = tier.value

    cap = get_storage_cap_bytes(tier)
    used = getattr(user, "storage_used_bytes", 0) or 0
    remaining = max(0, cap - used)

    if estimated_size_bytes > remaining:
        logger.warning(
            "storage_limit_exceeded user=%s tier=%s used=%d estimated=%d cap=%d",
            user.id, tier, used, estimated_size_bytes, cap,
        )
        raise HTTPException(
            status_code=402,
            detail=(
                f"Estimated storage ({estimated_size_bytes:,} bytes) exceeds your "
                f"remaining storage quota ({remaining:,} of {cap:,} bytes). "
                f"Upgrade your plan for more storage."
            ),
        )
