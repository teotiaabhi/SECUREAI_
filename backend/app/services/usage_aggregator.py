"""
Usage aggregator — queries and aggregates user consumption metrics
for billing dashboards and tier enforcement.

All queries are scoped to the authenticated user, enforcing tenant isolation.
"""

from datetime import date, datetime, timedelta, timezone
from typing import Dict, List, Optional
from uuid import UUID

from sqlalchemy import select, func, and_, extract
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.middleware.tier_limits import TIER_LIMITS, get_ai_tokens_per_day


# ── Storage caps per tier (bytes) ────────────────────────────
STORAGE_CAPS: Dict[str, int] = {
    "free": 500 * 1024 * 1024,            # 500 MB
    "pro": 5 * 1024 * 1024 * 1024,         # 5 GB
    "enterprise": 50 * 1024 * 1024 * 1024,  # 50 GB
}


def _resolve_tier(user) -> str:
    """Normalize tier to a string."""
    tier = getattr(user, "tier", "free")
    if hasattr(tier, "value"):
        tier = tier.value
    return tier


async def get_user_usage_summary(db: AsyncSession, user: User) -> Dict:
    """Return current usage vs. tier limits for the authenticated user.

    Returns:
        {
            "tier": str,
            "scans_today": int,
            "scans_this_month": int,
            "ai_tokens_today": int,
            "storage_used_bytes": int,
            "limits": {
                "scans_per_day": int,
                "ai_tokens_per_day": int,
                "max_files": int,
                "max_repo_size_mb": int,
                "storage_cap_bytes": int,
            },
            "usage_percent": {
                "scans_today": float,
                "ai_tokens_today": float,
                "storage": float,
            },
        }
    """
    tier = _resolve_tier(user)
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    storage_cap = STORAGE_CAPS.get(tier, STORAGE_CAPS["free"])

    # Daily scan count (from user model counter)
    today = date.today()
    scans_today = user.scans_today or 0
    ai_tokens_today = user.ai_tokens_used or 0
    if user.last_scan_reset is None or user.last_scan_reset < today:
        scans_today = 0
        ai_tokens_today = 0

    # Monthly scan count (from DB)
    month_start = today.replace(day=1)
    month_start_dt = datetime(month_start.year, month_start.month, month_start.day, tzinfo=timezone.utc)
    result = await db.execute(
        select(func.count(Scan.id)).where(
            Scan.user_id == user.id,
            Scan.created_at >= month_start_dt,
        )
    )
    scans_this_month = result.scalar_one() or 0

    storage_used = user.storage_used_bytes or 0

    scans_per_day = limits["scans_per_day"]
    ai_budget = limits["ai_tokens_per_day"]

    return {
        "tier": tier,
        "scans_today": scans_today,
        "scans_this_month": scans_this_month,
        "ai_tokens_today": ai_tokens_today,
        "storage_used_bytes": storage_used,
        "limits": {
            "scans_per_day": scans_per_day,
            "ai_tokens_per_day": ai_budget,
            "max_files": limits["max_files"],
            "max_repo_size_mb": limits["max_repo_size_mb"],
            "storage_cap_bytes": storage_cap,
        },
        "usage_percent": {
            "scans_today": round(
                (scans_today / scans_per_day * 100) if scans_per_day else 0, 1
            ),
            "ai_tokens_today": round(
                (ai_tokens_today / ai_budget * 100) if ai_budget else 0, 1
            ),
            "storage": round(
                (storage_used / storage_cap * 100) if storage_cap else 0, 1
            ),
        },
    }


async def record_scan_completion(
    db: AsyncSession,
    user_id: UUID,
    tokens_used: int,
    scan_mode: str = "full",
    storage_bytes: int = 0,
) -> None:
    """Increment user's AI token counter and storage after a scan finishes.

    Called from the orchestration layer post-pipeline.

    Args:
        db: Async database session.
        user_id: UUID of the user.
        tokens_used: AI tokens consumed by this scan.
        scan_mode: Scan mode for logging.
        storage_bytes: Total bytes of source files scanned.
    """
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    if not user:
        return

    # Record scan history entry
    from app.models.scan_history import ScanHistory
    history = ScanHistory(
        scan_id=None,  # Will be set below if we can find a recent scan
        user_id=user_id,
        tokens_used=tokens_used,
        files_scanned=0,
        duration=0.0,
    )
    # Try to find the most recent scan for this user to link
    from app.models.scan import Scan
    latest = await db.execute(
        select(Scan.id)
        .where(Scan.user_id == user_id)
        .order_by(Scan.created_at.desc())
        .limit(1)
    )
    latest_id = latest.scalar_one_or_none()
    if latest_id:
        history.scan_id = latest_id
        # Get files count from the scan
        scan_result = await db.execute(
            select(Scan.total_files, Scan.duration)
            .where(Scan.id == latest_id)
        )
        scan_row = scan_result.one_or_none()
        if scan_row:
            history.files_scanned = scan_row[0] or 0
            history.duration = scan_row[1] or 0.0
        db.add(history)

    user.ai_tokens_used = (user.ai_tokens_used or 0) + tokens_used
    user.storage_used_bytes = (user.storage_used_bytes or 0) + storage_bytes
    await db.flush()


async def get_monthly_usage_history(
    db: AsyncSession,
    user_id: UUID,
    months: int = 6,
) -> List[Dict]:
    """Return monthly aggregated usage for billing display.

    Returns list of:
        {
            "month": "2025-01",
            "scans": int,
            "total_files_scanned": int,
            "total_vulnerabilities": int,
        }
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=months * 31)

    result = await db.execute(
        select(
            extract("year", Scan.created_at).label("year"),
            extract("month", Scan.created_at).label("month"),
            func.count(Scan.id).label("scans"),
            func.coalesce(func.sum(Scan.total_files), 0).label("total_files"),
            func.coalesce(func.sum(Scan.total_vulnerabilities), 0).label("total_vulns"),
        )
        .where(
            Scan.user_id == user_id,
            Scan.created_at >= cutoff,
        )
        .group_by("year", "month")
        .order_by("year", "month")
    )
    rows = result.all()

    history = []
    for row in rows:
        year = int(row.year)
        month = int(row.month)
        history.append({
            "month": f"{year}-{month:02d}",
            "scans": row.scans,
            "total_files_scanned": row.total_files,
            "total_vulnerabilities": row.total_vulns,
        })

    return history
