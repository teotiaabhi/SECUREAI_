"""
Baseline Service — vulnerability baseline snapshot management.

Manages deterministic vulnerability fingerprints (detection_ids) that form
a repository's baseline. Used by the delta engine to determine which
findings are NEW, FIXED, or UNCHANGED between scans.

Responsibilities:
  - Store/upsert baselines after successful scans
  - Deactivate fixed findings (mark is_active=False)
  - Provide active baseline as {detection_id -> metadata} map
  - Prune old baselines per retention policy

No orchestration logic. No GitHub calls. No delta computation.
"""

import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import UUID

from sqlalchemy import select, update, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cicd import BaselineFinding
from app.models.vulnerability import Vulnerability
from app.core.logging import get_logger
from app.core.config import get_settings
from app.services.cache_service import baseline_cache

logger = get_logger("baseline_service")

# Line numbers are bucketed into ranges so that small shifts from
# nearby code additions/deletions don't change the detection_id.
_LINE_BUCKET_SIZE = 10


# ── Detection ID Computation ───────────────────────────────

def _normalize_line_range(line_reference: int) -> int:
    """Normalize a line number to a range bucket.

    Groups lines into _LINE_BUCKET_SIZE ranges so that small shifts
    (e.g., from adding/removing nearby code) don't change the detection_id.

    Examples (bucket=10): 1->0, 5->0, 10->0, 11->10, 25->20
    """
    if line_reference <= 0:
        return 0
    return ((line_reference - 1) // _LINE_BUCKET_SIZE) * _LINE_BUCKET_SIZE


def compute_detection_id(
    file_path: str,
    rule_id: str,
    line_reference: int,
    severity: str,
) -> str:
    """Compute a deterministic SHA-256 fingerprint for a vulnerability finding.

    The detection_id is a stable identifier that allows tracking whether
    a specific vulnerability is the "same" across different scans.

    Uses normalized line ranges (10-line buckets) instead of raw line
    numbers so that small line shifts from diffs don't break baseline
    comparison.

    Args:
        file_path: Path of the file containing the vulnerability.
        rule_id: Vulnerability type / rule identifier.
        line_reference: Line number where the vulnerability occurs.
        severity: Severity level (critical/high/medium/low/info).

    Returns:
        64-character hex SHA-256 digest.
    """
    normalized_line = _normalize_line_range(line_reference)
    raw = f"{file_path}|{rule_id}|{normalized_line}|{severity}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ── Store Baseline ──────────────────────────────────────────

async def store_baseline(
    db: AsyncSession,
    repo_id: UUID,
    scan_id: UUID,
    vulnerabilities: List[Vulnerability],
    commit_sha: str,
) -> int:
    """Store or update baseline finding fingerprints for a repository.

    Performs an upsert pattern:
    1. Mark all existing active findings as inactive.
    2. For each finding, compute its detection_id.
    3. If the detection_id already exists -> reactivate + update last_seen_at.
    4. If new -> insert with first_seen_at=now.

    This deactivation-then-reactivation pattern automatically marks
    findings that are no longer present (fixed) as is_active=False.

    Args:
        db: Async database session.
        repo_id: Repository UUID.
        scan_id: Scan UUID that produced these findings.
        vulnerabilities: List of Vulnerability ORM objects from the completed scan.
        commit_sha: Git commit SHA this baseline corresponds to.

    Returns:
        Number of baseline findings stored/updated.
    """
    now = datetime.now(timezone.utc)
    safe_sha = commit_sha[:40] if commit_sha else ""

    # Step 1: Mark all existing active findings as inactive.
    # Findings still present will be reactivated below.
    # Findings NOT present stay inactive → they are "fixed".
    await db.execute(
        update(BaselineFinding)
        .where(
            BaselineFinding.repository_id == repo_id,
            BaselineFinding.is_active.is_(True),
        )
        .values(is_active=False)
    )

    stored_count = 0
    seen_detection_ids: set = set()

    for vuln in vulnerabilities:
        detection_id = compute_detection_id(
            file_path=vuln.file_name,
            rule_id=vuln.vulnerability_type,
            line_reference=vuln.line_reference or 0,
            severity=vuln.severity,
        )

        # Skip duplicates within the same scan
        if detection_id in seen_detection_ids:
            continue
        seen_detection_ids.add(detection_id)

        # Step 2: Check if this detection_id already exists for this repo
        result = await db.execute(
            select(BaselineFinding).where(
                BaselineFinding.repository_id == repo_id,
                BaselineFinding.detection_id == detection_id,
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            # Step 3: Reactivate — finding still present
            existing.is_active = True
            existing.last_seen_at = now
            existing.scan_id = scan_id
            existing.commit_sha = safe_sha
        else:
            # Step 4: Insert new baseline finding
            baseline_finding = BaselineFinding(
                repository_id=repo_id,
                scan_id=scan_id,
                detection_id=detection_id,
                file_name=vuln.file_name,
                vulnerability_type=vuln.vulnerability_type,
                severity=vuln.severity,
                line_reference=vuln.line_reference or 0,
                commit_sha=safe_sha,
                is_active=True,
            )
            db.add(baseline_finding)

        stored_count += 1

    await db.flush()

    baseline_cache.invalidate(f"baseline:{repo_id}")

    logger.info(
        "baseline_stored",
        repo_id=str(repo_id),
        scan_id=str(scan_id),
        finding_count=stored_count,
        commit=safe_sha[:8],
    )
    return stored_count


# ── Get Active Baseline ─────────────────────────────────────

async def get_active_baseline(
    db: AsyncSession,
    repo_id: UUID,
) -> List[BaselineFinding]:
    """Get all active baseline findings for a repository.

    Uses in-memory cache (5 min TTL) to avoid repeated DB queries
    for the same repository baseline within a short window.

    Returns:
        List of BaselineFinding ORM objects where is_active=True.
    """
    cache_key = f"baseline:{repo_id}"
    cached = await baseline_cache.get(cache_key)
    if cached is not None:
        return cached

    result = await db.execute(
        select(BaselineFinding).where(
            BaselineFinding.repository_id == repo_id,
            BaselineFinding.is_active.is_(True),
        )
    )
    findings = list(result.scalars().all())
    await baseline_cache.set(cache_key, findings)
    return findings


async def get_active_baseline_map(
    db: AsyncSession,
    repo_id: UUID,
) -> Dict[str, dict]:
    """Get active baseline as a detection_id -> metadata mapping.

    Convenience method for the delta engine and API responses.

    Returns:
        Dict mapping detection_id to finding metadata:
        {
            "abc123...": {
                "file_name": "src/app.py",
                "vulnerability_type": "sql_injection",
                "severity": "high",
                "line_reference": 42,
                "scan_id": UUID(...),
                "commit_sha": "deadbeef",
            },
            ...
        }
    """
    findings = await get_active_baseline(db, repo_id)
    return {
        f.detection_id: {
            "file_name": f.file_name,
            "vulnerability_type": f.vulnerability_type,
            "severity": f.severity,
            "line_reference": f.line_reference,
            "scan_id": f.scan_id,
            "commit_sha": f.commit_sha,
        }
        for f in findings
    }


# ── Baseline Summary ────────────────────────────────────────

async def get_baseline_summary(
    db: AsyncSession,
    repo_id: UUID,
) -> dict:
    """Get a summary of the current baseline for a repository.

    Returns:
        dict with finding_count, severity breakdown, latest commit_sha,
        and latest scan_id.
    """
    findings = await get_active_baseline(db, repo_id)

    severity_counts: Dict[str, int] = {}
    latest_commit = ""
    latest_scan_id = None

    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        if f.commit_sha:
            latest_commit = f.commit_sha
        if f.scan_id:
            latest_scan_id = f.scan_id

    return {
        "finding_count": len(findings),
        "severity_counts": severity_counts,
        "commit_sha": latest_commit,
        "scan_id": latest_scan_id,
    }


# ── Retention / Pruning ─────────────────────────────────────

async def prune_old_baselines(
    db: AsyncSession,
    repo_id: UUID,
    keep_count: Optional[int] = None,
) -> int:
    """Prune inactive baseline findings, keeping only recent ones.

    Deletes inactive findings that are older than the Nth most recent scan.
    Active findings are never pruned.

    Args:
        db: Async database session.
        repo_id: Repository UUID.
        keep_count: Number of recent baselines to keep. Defaults to config value.

    Returns:
        Number of pruned findings.
    """
    if keep_count is None:
        settings = get_settings()
        keep_count = settings.BASELINE_RETENTION_COUNT

    # Find the N most recent scan_ids that have baseline findings
    result = await db.execute(
        select(BaselineFinding.scan_id)
        .where(BaselineFinding.repository_id == repo_id)
        .group_by(BaselineFinding.scan_id)
        .order_by(func.max(BaselineFinding.last_seen_at).desc())
        .limit(keep_count)
    )
    recent_scan_ids = {row[0] for row in result.all() if row[0] is not None}

    if not recent_scan_ids:
        return 0

    # Delete inactive findings not in recent scans
    del_result = await db.execute(
        delete(BaselineFinding).where(
            BaselineFinding.repository_id == repo_id,
            BaselineFinding.is_active.is_(False),
            BaselineFinding.scan_id.notin_(recent_scan_ids),
        )
    )

    pruned = del_result.rowcount
    if pruned:
        logger.info(
            "baseline_pruned",
            repo_id=str(repo_id),
            pruned_count=pruned,
            kept_scans=len(recent_scan_ids),
        )

    return pruned
