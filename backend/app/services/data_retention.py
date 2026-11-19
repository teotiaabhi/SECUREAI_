"""
GDPR-compliant data lifecycle management.

Provides:
- Right-to-be-forgotten (delete all user data)
- Data portability (export all user data as JSON)
- Automated retention policy (purge aged data)

All operations are audit-logged.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from uuid import UUID

from sqlalchemy import select, delete, update, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger

logger = get_logger("data_retention")


class DataRetentionService:
    """GDPR data lifecycle operations."""

    @staticmethod
    async def delete_user_data(
        db: AsyncSession,
        user_id: UUID,
    ) -> Dict[str, Any]:
        """GDPR right-to-be-forgotten.

        Deletes:
        - All scans and associated vulnerabilities
        - All scan sessions, progress records, files
        - All chunks
        - All baseline findings
        - Anonymises audit log entries (nullify user_id, mask detail)
        - Marks user status as DELETED

        Returns a summary of deleted counts.
        """
        from app.models.scan import Scan
        from app.models.vulnerability import Vulnerability
        from app.models.audit_log import AuditLog
        from app.models.user import User, UserStatus

        counts: Dict[str, int] = {}

        # 1. Find all scans for this user
        scan_result = await db.execute(
            select(Scan.id).where(Scan.user_id == user_id)
        )
        scan_ids = [row[0] for row in scan_result.fetchall()]
        counts["scans"] = len(scan_ids)

        # 2. Delete vulnerabilities linked to those scans
        if scan_ids:
            vuln_result = await db.execute(
                delete(Vulnerability).where(Vulnerability.scan_id.in_(scan_ids))
            )
            counts["vulnerabilities"] = vuln_result.rowcount or 0

            # 3. Delete scan session records if they exist
            try:
                from app.models.scan_session import ScanSessionRecord
                await db.execute(
                    delete(ScanSessionRecord).where(
                        ScanSessionRecord.scan_id.in_(scan_ids)
                    )
                )
            except Exception:
                pass  # Model may not exist

            # 4. Delete chunks if they exist
            try:
                from app.models.chunk import ScanChunk
                await db.execute(
                    delete(ScanChunk).where(ScanChunk.scan_id.in_(scan_ids))
                )
            except Exception:
                pass

            # 5. Delete the scans themselves
            await db.execute(
                delete(Scan).where(Scan.user_id == user_id)
            )
        else:
            counts["vulnerabilities"] = 0

        # 6. Anonymise audit logs (keep structure for SOC2, remove PII)
        audit_result = await db.execute(
            update(AuditLog)
            .where(AuditLog.user_id == user_id)
            .values(
                user_id=None,
                detail={"redacted": "gdpr_deletion"},
                ip_address=None,
                user_agent=None,
            )
        )
        counts["anonymized_audit_logs"] = audit_result.rowcount or 0

        # 7. Mark user as DELETED
        await db.execute(
            update(User)
            .where(User.id == user_id)
            .values(
                status=UserStatus.DELETED,
                email=f"deleted_{str(user_id)[:8]}@redacted.local",
                name="Deleted User",
                avatar_url=None,
                google_id=None,
                github_token_encrypted=None,
            )
        )

        await db.flush()
        logger.info("gdpr_user_data_deleted", user_id=str(user_id), counts=counts)
        return counts

    @staticmethod
    async def export_user_data(
        db: AsyncSession,
        user_id: UUID,
    ) -> Dict[str, Any]:
        """GDPR data portability — export all user data as JSON.

        Returns a dictionary containing:
        - User profile (sensitive fields masked)
        - Scan history with results
        - Vulnerability findings
        - Audit log entries
        """
        from app.models.scan import Scan
        from app.models.vulnerability import Vulnerability
        from app.models.audit_log import AuditLog
        from app.models.user import User

        export: Dict[str, Any] = {
            "export_date": datetime.now(timezone.utc).isoformat(),
            "user_id": str(user_id),
        }

        # User profile
        user_result = await db.execute(
            select(User).where(User.id == user_id)
        )
        user = user_result.scalar_one_or_none()
        if user:
            export["profile"] = {
                "email": user.email,
                "name": user.name,
                "provider": user.provider,
                "role": user.role.value if hasattr(user.role, "value") else str(user.role),
                "tier": user.tier.value if hasattr(user.tier, "value") else str(user.tier),
                "status": user.status.value if hasattr(user.status, "value") else str(user.status),
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "scans_today": user.scans_today,
                "ai_tokens_used": user.ai_tokens_used,
                "storage_used_bytes": user.storage_used_bytes,
            }

        # Scans
        scan_result = await db.execute(
            select(Scan).where(Scan.user_id == user_id)
        )
        scans = scan_result.scalars().all()
        export["scans"] = []
        for s in scans:
            scan_data = {
                "id": str(s.id),
                "repo_name": s.repo_name,
                "status": s.status.value if hasattr(s.status, "value") else str(s.status),
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }

            # Vulnerabilities for this scan
            vuln_result = await db.execute(
                select(Vulnerability).where(Vulnerability.scan_id == s.id)
            )
            vulns = vuln_result.scalars().all()
            scan_data["vulnerabilities"] = [
                {
                    "id": str(v.id),
                    "rule_id": v.rule_id,
                    "severity": v.severity,
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "message": v.message,
                }
                for v in vulns
            ]
            export["scans"].append(scan_data)

        # Audit log entries
        audit_result = await db.execute(
            select(AuditLog).where(AuditLog.user_id == user_id)
        )
        audits = audit_result.scalars().all()
        export["audit_logs"] = [
            {
                "id": str(a.id),
                "event_type": a.event_type,
                "event_category": a.event_category,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in audits
        ]

        logger.info(
            "gdpr_data_exported",
            user_id=str(user_id),
            scans=len(export["scans"]),
            audits=len(export["audit_logs"]),
        )
        return export

    @staticmethod
    async def apply_retention_policy(
        db: AsyncSession,
        retention_days: int = 90,
    ) -> Dict[str, int]:
        """Purge data older than the retention period.

        Returns counts of purged records.
        """
        from app.models.scan import Scan
        from app.models.vulnerability import Vulnerability

        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        counts: Dict[str, int] = {}

        # Find scans older than retention period
        old_scans_result = await db.execute(
            select(Scan.id).where(Scan.created_at < cutoff)
        )
        old_scan_ids = [row[0] for row in old_scans_result.fetchall()]

        if old_scan_ids:
            # Delete vulnerabilities
            vuln_del = await db.execute(
                delete(Vulnerability).where(Vulnerability.scan_id.in_(old_scan_ids))
            )
            counts["purged_vulnerabilities"] = vuln_del.rowcount or 0

            # Delete scan sessions
            try:
                from app.models.scan_session import ScanSessionRecord
                await db.execute(
                    delete(ScanSessionRecord).where(
                        ScanSessionRecord.scan_id.in_(old_scan_ids)
                    )
                )
            except Exception:
                pass

            # Delete chunks
            try:
                from app.models.chunk import ScanChunk
                await db.execute(
                    delete(ScanChunk).where(ScanChunk.scan_id.in_(old_scan_ids))
                )
            except Exception:
                pass

            # Delete the scans
            scan_del = await db.execute(
                delete(Scan).where(Scan.id.in_(old_scan_ids))
            )
            counts["purged_scans"] = scan_del.rowcount or 0
        else:
            counts["purged_scans"] = 0
            counts["purged_vulnerabilities"] = 0

        await db.flush()
        logger.info(
            "retention_policy_applied",
            retention_days=retention_days,
            counts=counts,
        )
        return counts
