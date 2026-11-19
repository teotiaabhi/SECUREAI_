"""
Scan insert service — transactional scan + bulk vulnerability insert against Supabase.
"""

from typing import List
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import Vulnerability
from app.core.logging import get_logger

logger = get_logger("scan_insert_service")


async def insert_scan_with_vulnerabilities(
    db: AsyncSession,
    *,
    user_id: UUID,
    repo_name: str,
    total_files: int,
    security_score: float,
    confidence_score: float,
    grade: str,
    config: dict | None = None,
    duration: float = 0.0,
    vulnerabilities: List[dict],
) -> Scan:
    """
    Insert a completed scan and its vulnerabilities in a single transaction.
    Rolls back everything if any insert fails.

    Each vulnerability dict must contain:
        file_name, vulnerability_type, severity, confidence,
        impact, remediation, owasp_mapping
    Optional: line_reference, exploit_example, category, code_snippet
    """
    try:
        # Count severities
        critical = sum(1 for v in vulnerabilities if v.get("severity") == "critical")
        high = sum(1 for v in vulnerabilities if v.get("severity") == "high")
        medium = sum(1 for v in vulnerabilities if v.get("severity") == "medium")
        low = sum(1 for v in vulnerabilities if v.get("severity") == "low")
        info = sum(1 for v in vulnerabilities if v.get("severity") == "info")

        # 1. Insert scan record
        scan = Scan(
            user_id=user_id,
            repo_name=repo_name,
            status=ScanStatus.COMPLETE,
            total_files=total_files,
            total_vulnerabilities=len(vulnerabilities),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            info_count=info,
            security_score=security_score,
            confidence_score=confidence_score,
            grade=grade,
            config=config or {},
            duration=duration,
        )
        db.add(scan)
        await db.flush()  # Get scan.id for FK

        # 2. Bulk insert vulnerabilities
        if vulnerabilities:
            vuln_objects = [
                Vulnerability(
                    scan_id=scan.id,
                    file_name=v["file_name"],
                    vulnerability_type=v["vulnerability_type"],
                    severity=v["severity"],
                    confidence=v.get("confidence", 0.0),
                    line_reference=v.get("line_reference"),
                    impact=v.get("impact"),
                    remediation=v.get("remediation"),
                    exploit_example=v.get("exploit_example"),
                    owasp_mapping=v.get("owasp_mapping"),
                    category=v.get("category"),
                    code_snippet=v.get("code_snippet"),
                )
                for v in vulnerabilities
            ]
            db.add_all(vuln_objects)

        await db.flush()
        logger.info(
            "scan_inserted",
            scan_id=str(scan.id),
            repo=repo_name,
            vulns=len(vulnerabilities),
        )
        return scan

    except Exception as e:
        logger.error("scan_insert_failed", error=str(e), repo=repo_name)
        raise  # Let the get_db dependency handle rollback


async def get_scans_for_user(
    db: AsyncSession,
    user_id: UUID,
    limit: int = 50,
    offset: int = 0,
) -> List[Scan]:
    """Fetch scans filtered by user_id. Never returns all users' data."""
    result = await db.execute(
        select(Scan)
        .where(Scan.user_id == user_id)
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(result.scalars().all())
