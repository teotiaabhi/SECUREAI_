"""
CI/CD API Routes — repository management, delta reports, timelines, manual triggers.

Provides REST endpoints for connecting GitHub repositories, viewing
vulnerability deltas, timelines, and manually triggering scans.
"""

from uuid import UUID
from typing import List

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.auth.jwt_handler import get_current_user
from app.models.user import User
from app.models.scan import Scan, ScanStatus
from app.models.cicd import Repository, Commit, ScanMode, VulnerabilityDelta
from app.models.vulnerability import Vulnerability
from app.schemas.cicd import (
    RepositoryConnectRequest,
    RepositoryResponse,
    RepositoryDetailResponse,
    ManualTriggerRequest,
    ScanModeSchema,
    DeltaFinding,
    DeltaReportResponse,
    DeltaSummary,
    BaselineResponse,
    TimelineEntry,
    TimelineResponse,
)
from app.services.github_webhook import generate_webhook_secret
from app.services.baseline_service import get_active_baseline, get_baseline_summary
from app.core.security import decrypt_token
from app.core.logging import get_logger
from app.core.config import get_settings

logger = get_logger("api_cicd")
router = APIRouter(prefix="/cicd", tags=["CI/CD"])


def _get_session_manager(request: Request):
    """Get the ScanSessionManager from app state."""
    manager = getattr(request.app.state, "session_manager", None)
    if manager is None:
        raise HTTPException(
            status_code=503,
            detail="Scan service not available — server starting up",
        )
    return manager


# ── Repository Management ─────────────────────────────────


@router.post("/repositories", response_model=RepositoryDetailResponse)
async def connect_repository(
    body: RepositoryConnectRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Connect a GitHub repository for CI/CD scanning.

    Verifies the user has access to the repository via GitHub API,
    creates a Repository record with a generated webhook secret,
    and returns the webhook URL + secret for setup.
    """
    # Verify user has GitHub token
    if not user.github_token_encrypted:
        raise HTTPException(
            status_code=400,
            detail="No GitHub account linked. Please connect GitHub first.",
        )

    token = decrypt_token(user.github_token_encrypted)
    settings = get_settings()

    # Verify user has access to the repo via GitHub API
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"https://api.github.com/repos/{body.repo_full_name}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
            if resp.status_code == 404:
                raise HTTPException(
                    status_code=404,
                    detail=f"Repository '{body.repo_full_name}' not found or you don't have access",
                )
            resp.raise_for_status()
            repo_data = resp.json()
    except httpx.HTTPStatusError:
        raise
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("github_api_error", error=str(exc))
        raise HTTPException(status_code=502, detail="Failed to verify repository access")

    github_repo_id = repo_data["id"]

    # Check if already connected
    result = await db.execute(
        select(Repository).where(Repository.github_repo_id == github_repo_id)
    )
    existing = result.scalar_one_or_none()

    if existing:
        if existing.user_id == user.id:
            # Already connected by this user — return existing
            webhook_url = f"{settings.API_PREFIX}/webhooks/github"
            return RepositoryDetailResponse(
                id=existing.id,
                full_name=existing.full_name,
                github_repo_id=existing.github_repo_id,
                default_branch=existing.default_branch,
                is_active=existing.is_active,
                installed_at=existing.installed_at,
                updated_at=existing.updated_at,
                webhook_url=webhook_url,
                webhook_secret=existing.webhook_secret,
            )
        else:
            raise HTTPException(
                status_code=409,
                detail="Repository already connected by another user",
            )

    # Create repository record
    webhook_secret = generate_webhook_secret()
    repo = Repository(
        user_id=user.id,
        github_repo_id=github_repo_id,
        full_name=body.repo_full_name,
        default_branch=body.default_branch or repo_data.get("default_branch", "main"),
        webhook_secret=webhook_secret,
        is_active=True,
    )
    db.add(repo)
    await db.flush()
    await db.commit()

    webhook_url = f"{settings.API_PREFIX}/webhooks/github"

    logger.info(
        "repository_connected",
        repo=body.repo_full_name,
        user_id=str(user.id),
    )

    return RepositoryDetailResponse(
        id=repo.id,
        full_name=repo.full_name,
        github_repo_id=repo.github_repo_id,
        default_branch=repo.default_branch,
        is_active=repo.is_active,
        installed_at=repo.installed_at,
        updated_at=repo.updated_at,
        webhook_url=webhook_url,
        webhook_secret=webhook_secret,
    )


@router.get("/repositories", response_model=List[RepositoryResponse])
async def list_repositories(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List user's connected repositories."""
    result = await db.execute(
        select(Repository)
        .where(Repository.user_id == user.id)
        .order_by(desc(Repository.installed_at))
    )
    repos = result.scalars().all()
    return [RepositoryResponse.model_validate(r) for r in repos]


@router.delete("/repositories/{repo_id}")
async def disconnect_repository(
    repo_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Disconnect a repository from CI/CD scanning."""
    result = await db.execute(
        select(Repository).where(
            Repository.id == repo_id,
            Repository.user_id == user.id,
        )
    )
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    # Soft-delete: mark as inactive
    repo.is_active = False
    await db.commit()

    logger.info(
        "repository_disconnected",
        repo=repo.full_name,
        user_id=str(user.id),
    )

    return {"message": f"Repository '{repo.full_name}' disconnected"}


# ── Vulnerability Timeline ────────────────────────────────


@router.get("/repositories/{repo_id}/timeline", response_model=TimelineResponse)
async def get_vulnerability_timeline(
    repo_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get vulnerability trend over time for a connected repository.

    Returns chronological scan entries with security scores,
    finding counts, and delta information.
    """
    # Verify ownership
    result = await db.execute(
        select(Repository).where(
            Repository.id == repo_id,
            Repository.user_id == user.id,
        )
    )
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    # Fetch scans for this repo, ordered chronologically
    result = await db.execute(
        select(Scan)
        .where(
            Scan.repository_id == repo_id,
            Scan.status == ScanStatus.COMPLETE.value,
        )
        .order_by(Scan.created_at)
        .limit(100)
    )
    scans = result.scalars().all()

    entries = []
    for scan in scans:
        # Get delta info if available
        delta_result = await db.execute(
            select(VulnerabilityDelta).where(
                VulnerabilityDelta.scan_id == scan.id
            )
        )
        delta = delta_result.scalar_one_or_none()

        entries.append(TimelineEntry(
            scan_id=scan.id,
            commit_sha=scan.head_commit_sha or "",
            scan_mode=scan.scan_mode or "full",
            security_score=scan.security_score or 0.0,
            risk_score=scan.security_score or 0.0,
            total_findings=scan.total_vulnerabilities or 0,
            new_findings=delta.new_count if delta else 0,
            fixed_findings=delta.fixed_count if delta else 0,
            created_at=scan.created_at,
        ))

    return TimelineResponse(
        repository=repo.full_name,
        entries=entries,
    )


# ── Delta Reports ─────────────────────────────────────────


@router.get("/delta/{scan_id}", response_model=DeltaReportResponse)
async def get_delta_report(
    scan_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get vulnerability delta report for a scan.

    Returns the NEW, FIXED, and UNCHANGED classification for each
    finding, along with regression detection status.
    """
    # Verify ownership
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get delta record
    result = await db.execute(
        select(VulnerabilityDelta).where(VulnerabilityDelta.scan_id == scan_id)
    )
    delta = result.scalar_one_or_none()

    if not delta:
        raise HTTPException(
            status_code=404,
            detail="No delta report available for this scan",
        )

    detail = delta.delta_detail or {}

    # Build DeltaFinding objects for new and fixed
    new_findings = [
        DeltaFinding(
            file_name=f.get("file_name", ""),
            vulnerability_type=f.get("vulnerability_type", ""),
            severity=f.get("severity", "info"),
            confidence=f.get("confidence", 0.0),
            line_reference=f.get("line_reference"),
            detection_id=f.get("detection_id", ""),
            status="new",
        )
        for f in detail.get("new_findings", [])
    ]

    fixed_findings = [
        DeltaFinding(
            file_name=f.get("file_name", ""),
            vulnerability_type=f.get("vulnerability_type", ""),
            severity=f.get("severity", "info"),
            confidence=0.0,
            line_reference=f.get("line_reference"),
            detection_id=f.get("detection_id", ""),
            status="fixed",
        )
        for f in detail.get("fixed_findings", [])
    ]

    return DeltaReportResponse(
        scan_id=scan.id,
        baseline_scan_id=delta.baseline_scan_id,
        new_findings=new_findings,
        fixed_findings=fixed_findings,
        unchanged_findings=[],
        regression_detected=delta.regression_detected,
        summary=DeltaSummary(
            new_count=delta.new_count,
            fixed_count=delta.fixed_count,
            unchanged_count=delta.unchanged_count,
            severity_breakdown=detail.get("severity_summary", {}),
        ),
    )


# ── Baseline ──────────────────────────────────────────────


@router.get("/repositories/{repo_id}/baseline", response_model=BaselineResponse)
async def get_baseline(
    repo_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the current baseline summary for a repository."""
    # Verify ownership
    result = await db.execute(
        select(Repository).where(
            Repository.id == repo_id,
            Repository.user_id == user.id,
        )
    )
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    summary = await get_baseline_summary(db, repo_id)

    # Get the latest scan_id from baseline findings
    baseline_findings = await get_active_baseline(db, repo_id)
    latest_scan_id = None
    latest_created_at = None
    for bf in baseline_findings:
        if bf.scan_id and (latest_created_at is None or bf.last_seen_at > latest_created_at):
            latest_scan_id = bf.scan_id
            latest_created_at = bf.last_seen_at

    from datetime import datetime, timezone
    return BaselineResponse(
        scan_id=latest_scan_id,
        commit_sha=summary["commit_sha"],
        finding_count=summary["finding_count"],
        severity_counts=summary.get("severity_counts", {}),
        created_at=latest_created_at or datetime.now(timezone.utc),
    )


# ── Manual Trigger ────────────────────────────────────────


@router.post("/trigger/{repo_id}")
async def manual_trigger(
    repo_id: UUID,
    body: ManualTriggerRequest,
    http_request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Manually trigger a scan (full or diff) for a connected repository.

    Useful for re-scanning or triggering scans outside of webhook events.
    """
    # Verify ownership
    result = await db.execute(
        select(Repository).where(
            Repository.id == repo_id,
            Repository.user_id == user.id,
        )
    )
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    if not repo.is_active:
        raise HTTPException(status_code=400, detail="Repository is not active")

    session_manager = _get_session_manager(http_request)

    # Determine scan mode
    scan_mode = body.scan_mode.value if body.scan_mode in (ScanModeSchema.FULL, ScanModeSchema.DIFF) else "full"
    branch = body.branch or repo.default_branch

    # Create scan record
    scan = Scan(
        user_id=user.id,
        repo_name=repo.full_name,
        status=ScanStatus.PENDING,
        scan_mode=scan_mode,
        repository_id=repo.id,
        base_commit_sha=body.base_commit[:40] if body.base_commit else None,
        head_commit_sha=body.head_commit[:40] if body.head_commit else None,
        config={
            "depth": "standard",
            "categories": {},
            "ai_reasoning": True,
            "manual_trigger": True,
        },
    )
    db.add(scan)
    await db.flush()

    # Enqueue
    from app.orchestration.session_manager import ConcurrencyLimitError
    try:
        is_paid = getattr(user, "is_paid", False)
        result = await session_manager.enqueue_scan(
            db=db,
            scan_id=scan.id,
            user_id=user.id,
            is_paid=is_paid,
            source_type="github",
            repo_url=f"https://github.com/{repo.full_name}",
            branch=branch,
        )
    except ConcurrencyLimitError as e:
        scan.status = ScanStatus.FAILED
        scan.error_message = str(e)
        await db.commit()
        raise HTTPException(status_code=429, detail=str(e))

    await db.commit()

    logger.info(
        "manual_scan_triggered",
        repo=repo.full_name,
        scan_id=str(scan.id),
        scan_mode=scan_mode,
    )

    return {
        "scan_id": str(scan.id),
        "status": ScanStatus.QUEUED.value,
        "scan_mode": scan_mode,
        "queue_position": result.get("queue_position", 0),
    }
