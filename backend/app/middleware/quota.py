"""
Quota enforcement dependencies — check_scan_quota / check_token_quota.

Use these as FastAPI Depends() to gate scan or AI endpoints.
Daily counters are reset atomically when a new day is detected.
"""

import logging
from datetime import date

from fastapi import Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.auth.jwt_handler import get_current_user
from app.models.user import User
from app.middleware.tier_limits import TIER_LIMITS

logger = logging.getLogger("middleware.quota")


def _resolve_tier(user: User) -> str:
    tier = getattr(user, "tier", "free")
    if hasattr(tier, "value"):
        tier = tier.value
    return tier


async def _ensure_daily_reset(user: User, db: AsyncSession) -> None:
    """Reset daily counters if the day has changed. Flushes within the session."""
    today = date.today()
    if user.last_scan_reset is None or user.last_scan_reset < today:
        user.scans_today = 0
        user.ai_tokens_used = 0
        user.last_scan_reset = today
        await db.flush()


async def check_scan_quota(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Dependency: reject with 429 if the user has exhausted daily scans."""
    await _ensure_daily_reset(user, db)

    tier = _resolve_tier(user)
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    max_scans = limits["scans_per_day"]

    if (user.scans_today or 0) >= max_scans:
        logger.warning(
            "scan_quota_blocked user=%s tier=%s used=%d limit=%d",
            user.id, tier, user.scans_today, max_scans,
        )
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Daily scan limit reached",
                "limit": max_scans,
            },
        )
    return user


async def check_token_quota(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Dependency: reject with 429 if the user has exhausted daily tokens."""
    await _ensure_daily_reset(user, db)

    tier = _resolve_tier(user)
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    token_limit = limits["ai_tokens_per_day"]

    if (user.ai_tokens_used or 0) >= token_limit:
        logger.warning(
            "token_quota_blocked user=%s tier=%s used=%d limit=%d",
            user.id, tier, user.ai_tokens_used, token_limit,
        )
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Daily token quota exceeded",
                "limit": token_limit,
            },
        )
    return user
