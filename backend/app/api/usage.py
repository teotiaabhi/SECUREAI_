"""
Usage API — exposes consumption metrics for billing dashboards.

All endpoints require authentication and are scoped to the requesting user.
"""

from datetime import date

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.auth.jwt_handler import get_current_user
from app.models.user import User
from app.services.usage_aggregator import get_user_usage_summary, get_monthly_usage_history
from app.services.cost_estimator import estimate_scan_cost
from app.middleware.tier_limits import TIER_LIMITS

router = APIRouter(prefix="/usage", tags=["Usage"])


@router.get("")
async def usage_quota(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Current daily quota status — scans and tokens used / remaining."""
    tier = getattr(user, "tier", "free")
    if hasattr(tier, "value"):
        tier = tier.value
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])

    # Apply daily reset if needed
    today = date.today()
    scans_used = user.scans_today or 0
    tokens_used = user.ai_tokens_used or 0
    if user.last_scan_reset is None or user.last_scan_reset < today:
        scans_used = 0
        tokens_used = 0

    scan_limit = limits["scans_per_day"]
    token_limit = limits["ai_tokens_per_day"]

    return {
        "daily_scan_limit": scan_limit,
        "scans_used": scans_used,
        "scans_remaining": max(0, scan_limit - scans_used),
        "token_limit": token_limit,
        "tokens_used": tokens_used,
        "tokens_remaining": max(0, token_limit - tokens_used),
    }


@router.get("/summary")
async def usage_summary(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Current usage vs. tier limits for the authenticated user."""
    return await get_user_usage_summary(db, user)


@router.get("/current")
async def usage_current(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Current period usage for the authenticated user (frontend-facing)."""
    summary = await get_user_usage_summary(db, user)
    # Map to the shape the frontend expects
    return {
        "user_id": str(user.id),
        "tier": summary.get("tier", "free"),
        "period_start": summary.get("period_start", ""),
        "period_end": summary.get("period_end", ""),
        "scans_used": summary.get("scans_today", 0),
        "scans_limit": summary.get("limits", {}).get("scans_per_day", 0),
        "ai_tokens_used": summary.get("ai_tokens_today", 0),
        "ai_tokens_limit": summary.get("limits", {}).get("ai_tokens_per_day", 0),
        "storage_used_bytes": summary.get("storage_used_bytes", 0),
        "storage_limit_bytes": summary.get("limits", {}).get("storage_cap_bytes", 0),
    }


@router.get("/cost-estimate")
async def cost_estimate(
    user: User = Depends(get_current_user),
    file_count: int = Query(0, ge=0),
    total_size_bytes: int = Query(0, ge=0),
    scan_mode: str = Query("full"),
):
    """Pre-scan cost estimate for the frontend."""
    tier = getattr(user, "tier", "free")
    if hasattr(tier, "value"):
        tier = tier.value
    result = estimate_scan_cost(
        file_count=file_count,
        total_size_bytes=total_size_bytes,
        scan_mode=scan_mode,
        tier=tier,
        ai_tokens_already_used=getattr(user, "ai_tokens_used", 0) or 0,
    )
    return {
        "estimated_tokens": result["estimated_tokens"],
        "estimated_cost_usd": round(result["estimated_tokens"] * 0.00001, 4),
        "tokens_remaining": result["remaining_budget"],
        "allowed": result["within_budget"],
        "tier": tier,
        "scan_mode": scan_mode,
    }


@router.get("/history")
async def usage_history(
    months: int = 6,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Monthly usage history for billing display."""
    months = min(max(months, 1), 24)
    return await get_monthly_usage_history(db, user.id, months=months)


@router.get("/tiers")
async def get_tier_plans():
    """Return all tier plan configurations for the landing page.

    Public endpoint — no auth required.
    """
    plans = []
    for tier_name, limits in TIER_LIMITS.items():
        plans.append({
            "name": tier_name,
            "display_name": tier_name.capitalize(),
            "scans_per_day": limits["scans_per_day"],
            "max_repo_size_mb": limits["max_repo_size_mb"],
            "max_files": limits["max_files"],
            "ai_tokens_per_day": limits["ai_tokens_per_day"],
            "storage_cap_bytes": limits["storage_cap_bytes"],
            "storage_cap_display": _format_bytes(limits["storage_cap_bytes"]),
        })
    return {"tiers": plans}


def _format_bytes(b: int) -> str:
    """Human-readable byte size."""
    if b >= 1_073_741_824:
        return f"{b / 1_073_741_824:.0f} GB"
    if b >= 1_048_576:
        return f"{b / 1_048_576:.0f} MB"
    return f"{b / 1024:.0f} KB"
