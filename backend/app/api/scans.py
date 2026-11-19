"""
Scan API Routes — Start, status, results, history, delete, report, compare.

Uses the orchestration layer for scan lifecycle management:
- ScanSessionManager for queuing and concurrency control
- ScanProgressTracker for DB-persisted progress
- ReportAggregator for structured reports and comparisons
"""

import asyncio
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, UploadFile, File, Form, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.db.session import get_db
from app.auth.jwt_handler import get_current_user
from app.models.user import User
from app.models.scan import Scan, ScanStatus
from app.models.scan_session import ScanSessionRecord
from app.models.vulnerability import Vulnerability
from app.models.chunk import ScanChunk
from app.schemas.scan import (
    ScanStartRequest, ScanStatusResponse, ScanResultResponse,
    ScanHistoryItem, VulnerabilityResponse, ScanConfigRequest,
    ScanReportResponse, ScanCompareResponse,
)
from app.services.ingestion import ingest_paste, ingest_upload
from app.orchestration.session_manager import ScanSessionManager, ConcurrencyLimitError
from app.orchestration.progress_tracker import ScanProgressTracker
from app.orchestration.report_aggregator import ReportAggregator
from app.core.logging import get_logger
from app.core.config import get_settings
from app.middleware.tier_limits import enforce_scan_limits
from app.services.cost_estimator import estimate_scan_cost, check_budget_before_scan
from typing import List, Optional

logger = get_logger("api_scans")
router = APIRouter(prefix="/scan", tags=["Scanning"])


def _get_session_manager(request: Request) -> ScanSessionManager:
    """Get the ScanSessionManager from app state."""
    manager = getattr(request.app.state, "session_manager", None)
    if manager is None:
        raise HTTPException(
            status_code=503,
            detail="Scan service not available — server starting up",
        )
    return manager


@router.post("/start")
async def start_scan(
    request_body: ScanStartRequest,
    http_request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Start a new security scan via the orchestration pipeline."""
    session_manager = _get_session_manager(http_request)

    # Enforce tier-based scan limits
    await enforce_scan_limits(user, db)

    # Determine source type and repo info
    source_type = request_body.source_type
    repo_url = None
    branch = request_body.branch
    github_token = None

    if source_type == "github" and request_body.github_repo:
        repo_url = f"https://github.com/{request_body.github_repo.repo_full_name}"
        branch = branch or request_body.github_repo.branch
        # Token from user's linked GitHub account (stored encrypted)
        enc_token = getattr(user, "github_token_encrypted", None)
        if enc_token:
            try:
                from app.core.security import decrypt_token
                github_token = decrypt_token(enc_token)
            except Exception:
                logger.warning("Failed to decrypt GitHub token for user %s", user.id)

    # Pre-scan cost estimate and budget check
    tier = getattr(user, "tier", "free")
    if hasattr(tier, "value"):
        tier = tier.value

    # Calculate actual file count and size from the source
    pre_file_count = 0
    pre_total_size = 0
    if source_type == "paste" and request_body.code_paste:
        code_text = request_body.code_paste.code or ""
        pre_file_count = 1
        pre_total_size = len(code_text.encode("utf-8", errors="ignore"))

    cost_estimate = estimate_scan_cost(
        file_count=pre_file_count,
        total_size_bytes=pre_total_size,
        scan_mode=getattr(request_body, "scan_mode", "full") or "full",
        tier=tier,
        ai_tokens_already_used=getattr(user, "ai_tokens_used", 0) or 0,
    )
    check_budget_before_scan(user, cost_estimate["estimated_tokens"])

    # Create scan record
    scan = Scan(
        user_id=user.id,
        repo_name=request_body.repo_name,
        status=ScanStatus.PENDING,
        config={
            "depth": request_body.config.depth.value,
            "categories": request_body.config.categories.model_dump(),
            "ai_reasoning": request_body.config.ai_reasoning,
            "exploit_examples": request_body.config.exploit_examples,
            "secure_rewrite": request_body.config.secure_rewrite,
            "paste_language": (
                request_body.code_paste.language
                if source_type == "paste" and request_body.code_paste
                else None
            ),
            "github_token": github_token,
            "tag": request_body.tag,
            "commit": request_body.commit,
        },
    )
    db.add(scan)
    await db.flush()

    # For paste source, persist chunks before enqueuing
    if source_type == "paste" and request_body.code_paste:
        files = ingest_paste(
            request_body.code_paste.code,
            request_body.code_paste.filename,
            request_body.code_paste.language,
        )
        for f in files:
            chunk = ScanChunk(
                scan_id=scan.id,
                file_name=f.path or f.filename,
                chunk_content=f.content,
            )
            db.add(chunk)
        await db.flush()

    # Enqueue via orchestration
    try:
        is_paid = getattr(user, "is_paid", False)
        result = await session_manager.enqueue_scan(
            db=db,
            scan_id=scan.id,
            user_id=user.id,
            is_paid=is_paid,
            source_type=source_type,
            repo_url=repo_url,
            branch=branch,
        )
    except ConcurrencyLimitError as e:
        scan.status = ScanStatus.FAILED
        scan.error_message = str(e)
        await db.commit()
        raise HTTPException(status_code=429, detail=str(e))

    return {
        "scan_id": str(scan.id),
        "status": ScanStatus.QUEUED.value,
        "queue_position": result.get("queue_position", 0),
        "message": "Scan queued",
        "cost_estimate": cost_estimate,
    }


@router.post("/upload")
async def start_upload_scan(
    http_request: Request,
    files: List[UploadFile] = File(...),
    config: str = Form("{}"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Start scan with uploaded files via orchestration pipeline."""
    import json
    import os
    import tempfile
    import aiofiles

    session_manager = _get_session_manager(http_request)
    settings = get_settings()

    # Enforce tier-based scan limits
    await enforce_scan_limits(user, db)

    # Pre-scan cost estimate and budget check for uploads
    tier = getattr(user, "tier", "free")
    if hasattr(tier, "value"):
        tier = tier.value
    upload_file_count = len(files)
    upload_total_size = sum(f.size or 0 for f in files)
    cost_estimate = estimate_scan_cost(
        file_count=upload_file_count,
        total_size_bytes=upload_total_size,
        scan_mode="full",
        tier=tier,
        ai_tokens_already_used=getattr(user, "ai_tokens_used", 0) or 0,
    )
    check_budget_before_scan(user, cost_estimate["estimated_tokens"])

    # Per-file size validation
    for f in files:
        if f.size and f.size > settings.MAX_FILE_SIZE_MB * 1024 * 1024:
            raise HTTPException(
                status_code=413,
                detail=f"File {f.filename} exceeds {settings.MAX_FILE_SIZE_MB}MB limit",
            )

    # Parse config
    try:
        cfg = ScanConfigRequest(**json.loads(config)) if config != "{}" else ScanConfigRequest()
    except Exception:
        cfg = ScanConfigRequest()

    # Check if ZIP
    is_zip = len(files) == 1 and files[0].filename and files[0].filename.endswith(".zip")

    scan = Scan(
        user_id=user.id,
        repo_name=files[0].filename if len(files) == 1 else "uploaded-files",
        status=ScanStatus.PENDING,
        config={
            "depth": cfg.depth.value,
            "categories": cfg.categories.model_dump(),
            "ai_reasoning": cfg.ai_reasoning,
        },
    )
    db.add(scan)
    await db.flush()

    if is_zip:
        # Stream ZIP to temp file (avoids loading entire file into memory)
        temp_dir = settings.SCAN_TEMP_DIR or tempfile.gettempdir()
        zip_path = os.path.join(temp_dir, f"upload-{scan.id}.zip")
        max_zip_bytes = 500 * 1024 * 1024  # 500 MB

        total_written = 0
        async with aiofiles.open(zip_path, "wb") as f:
            while True:
                chunk = await files[0].read(262144)  # 256 KB chunks
                if not chunk:
                    break
                total_written += len(chunk)
                if total_written > max_zip_bytes:
                    # Clean up partial file
                    await f.close()
                    try:
                        os.unlink(zip_path)
                    except OSError:
                        pass
                    raise HTTPException(
                        status_code=413,
                        detail=f"ZIP file exceeds 500MB upload limit",
                    )
                await f.write(chunk)

        scan.config = {**scan.config, "zip_path": zip_path}
        await db.flush()

        source_type = "zip"
    else:
        # Regular file upload — persist as chunks
        ingested = await ingest_upload(files)
        for f in ingested:
            chunk = ScanChunk(
                scan_id=scan.id,
                file_name=f.path or f.filename,
                chunk_content=f.content,
            )
            db.add(chunk)
        await db.flush()
        source_type = "upload"

    # Enqueue via orchestration
    try:
        is_paid = getattr(user, "is_paid", False)
        result = await session_manager.enqueue_scan(
            db=db,
            scan_id=scan.id,
            user_id=user.id,
            is_paid=is_paid,
            source_type=source_type,
        )
    except ConcurrencyLimitError as e:
        scan.status = ScanStatus.FAILED
        scan.error_message = str(e)
        await db.commit()
        raise HTTPException(status_code=429, detail=str(e))

    return {
        "scan_id": str(scan.id),
        "status": ScanStatus.QUEUED.value,
        "queue_position": result.get("queue_position", 0),
        "files_ingested": len(files),
        "cost_estimate": cost_estimate,
    }


@router.get("/status/{scan_id}", response_model=ScanStatusResponse)
async def get_status(scan_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Get scan progress/status — read-only, never performs scanning work.

    Reads from DB-persisted progress tracker and supplements with
    the in-memory progress store for real-time per-file granularity.

    Part 5: This endpoint NEVER crashes — all exceptions produce
    safe fallback responses.
    """
    try:
        result = await db.execute(
            select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id)
        )
        scan = result.scalar_one_or_none()
    except Exception:
        raise HTTPException(status_code=503, detail="Database temporarily unavailable")

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get DB-persisted progress — always returns dict
    try:
        progress = await ScanProgressTracker.get_progress(db, scan_id)
    except Exception:
        progress = {}

    # Supplement with in-memory progress (more granular, per-file updates)
    try:
        from app.orchestration.parallel_controller import get_scan_progress
        mem_progress = get_scan_progress(str(scan_id))
        if mem_progress and isinstance(mem_progress, dict):
            mem_scanned = int(mem_progress.get("files_scanned", 0) or 0)
            db_scanned = int(progress.get("files_scanned") or 0)
            if mem_scanned >= db_scanned:
                progress["files_scanned"] = mem_scanned
                progress["total_files"] = mem_progress.get(
                    "files_total", progress.get("total_files", 0)
                )
                progress["current_file"] = mem_progress.get(
                    "current_file", progress.get("current_file", "")
                )
    except Exception:
        # In-memory progress unavailable — continue with DB-only data
        pass

    # Normalize status to string (handles both enum and plain string)
    try:
        status_str = scan.status.value if hasattr(scan.status, 'value') else str(scan.status or "unknown")
    except Exception:
        status_str = "unknown"
    phase_str = progress.get("phase") or status_str

    try:
        return ScanStatusResponse(
            id=scan.id,
            status=status_str,
            phase=phase_str,
            progress_percent=float(progress.get("percent") or 0.0),
            current_file=str(progress.get("current_file") or ""),
            files_scanned=int(progress.get("files_scanned") or 0),
            total_files=int(progress.get("total_files") or scan.total_files or 0),
            chunks_processed=int(progress.get("files_scanned") or 0),
            total_chunks=int(progress.get("total_files") or 0),
            estimated_time_remaining=float(progress.get("eta_seconds") or 0.0),
            live_vuln_count=int(progress.get("live_vuln_count") or 0),
        )
    except Exception:
        # Part 5: absolute last resort — return minimal safe response
        return ScanStatusResponse(
            id=scan.id,
            status=status_str,
            phase=status_str,
            progress_percent=0.0,
            current_file="",
            files_scanned=0,
            total_files=int(scan.total_files or 0),
            chunks_processed=0,
            total_chunks=0,
            estimated_time_remaining=0.0,
            live_vuln_count=0,
        )


@router.get("/result/{scan_id}", response_model=ScanResultResponse)
async def get_result(scan_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Get scan results with vulnerabilities."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    vulns_result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    )
    vulnerabilities = vulns_result.scalars().all()

    # Normalize status to string
    status_str = scan.status.value if hasattr(scan.status, 'value') else str(scan.status or "unknown")

    return ScanResultResponse(
        id=scan.id,
        repo_name=scan.repo_name or "",
        status=status_str,
        total_files=scan.total_files or 0,
        total_vulnerabilities=scan.total_vulnerabilities or 0,
        critical_count=scan.critical_count or 0,
        high_count=scan.high_count or 0,
        medium_count=scan.medium_count or 0,
        low_count=scan.low_count or 0,
        info_count=scan.info_count or 0,
        security_score=scan.security_score or 0.0,
        confidence_score=scan.confidence_score or 0.0,
        grade=scan.grade or "",
        duration=scan.duration or 0.0,
        created_at=scan.created_at,
        vulnerabilities=[VulnerabilityResponse.model_validate(v) for v in vulnerabilities],
    )


@router.get("/report/{scan_id}", response_model=ScanReportResponse)
async def get_report(scan_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Get structured scan report with analytics."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_status = scan.status.value if hasattr(scan.status, 'value') else str(scan.status or "")
    if scan_status != ScanStatus.COMPLETE.value:
        raise HTTPException(status_code=400, detail="Scan not complete")

    report_data = scan.report_data
    if not report_data:
        raise HTTPException(status_code=404, detail="Report data not available")

    return ScanReportResponse(
        security_score=report_data.get("security_score", 0.0),
        confidence_score=report_data.get("confidence_score", 0.0),
        grade=report_data.get("grade", ""),
        total_files=report_data.get("total_files", 0),
        total_findings=report_data.get("total_findings", 0),
        severity_counts=report_data.get("severity_counts", {}),
        owasp_distribution=report_data.get("owasp_distribution", {}),
        cwe_distribution=report_data.get("cwe_distribution", {}),
        category_distribution=report_data.get("category_distribution", {}),
        file_risk_ranking=report_data.get("file_risk_ranking", []),
        executive_summary=report_data.get("executive_summary", ""),
        posture_summary=report_data.get("posture_summary", ""),
    )


@router.get("/compare/{scan_id_1}/{scan_id_2}", response_model=ScanCompareResponse)
async def compare_scans(
    scan_id_1: UUID,
    scan_id_2: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Compare two scan reports and return a diff summary."""
    # Load both scans (must belong to user)
    result_1 = await db.execute(
        select(Scan).where(Scan.id == scan_id_1, Scan.user_id == user.id)
    )
    scan_1 = result_1.scalar_one_or_none()
    if not scan_1:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id_1} not found")

    result_2 = await db.execute(
        select(Scan).where(Scan.id == scan_id_2, Scan.user_id == user.id)
    )
    scan_2 = result_2.scalar_one_or_none()
    if not scan_2:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id_2} not found")

    if not scan_1.report_data or not scan_2.report_data:
        raise HTTPException(
            status_code=400,
            detail="Both scans must be complete with report data",
        )

    aggregator = ReportAggregator()
    comparison = aggregator.compare_scans(scan_1.report_data, scan_2.report_data)

    return ScanCompareResponse(
        score_delta=comparison["score_delta"],
        grade_change=comparison["grade_change"],
        vuln_delta=comparison["vuln_delta"],
        total_delta=comparison["total_delta"],
        trend=comparison["trend"],
    )


@router.get("/history", response_model=List[ScanHistoryItem])
async def get_history(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Get user's scan history."""
    result = await db.execute(
        select(Scan)
        .where(Scan.user_id == user.id)
        .order_by(desc(Scan.created_at))
        .limit(50)
    )
    scans = result.scalars().all()
    return [ScanHistoryItem.model_validate(s) for s in scans]


@router.delete("/delete/{scan_id}")
async def delete_scan(scan_id: UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Delete a scan and its vulnerabilities."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    await db.delete(scan)
    logger.info("scan_deleted", scan_id=str(scan_id))
    return {"message": "Scan deleted"}


@router.post("/cancel/{scan_id}")
async def cancel_scan_endpoint(
    scan_id: UUID,
    http_request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Cancel a running scan via the orchestration session manager."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    terminal_statuses = {ScanStatus.COMPLETE.value, ScanStatus.FAILED.value, ScanStatus.CANCELLED.value}
    scan_status = scan.status.value if hasattr(scan.status, 'value') else str(scan.status or "")
    if scan_status in terminal_statuses:
        raise HTTPException(status_code=400, detail="Scan is not running")

    session_manager = _get_session_manager(http_request)
    await session_manager.cancel(scan_id, db)

    return {"message": "Scan cancelled"}
