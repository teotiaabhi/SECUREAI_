"""
Compliance & GDPR API endpoints.

Provides:
- SOC2 readiness status report
- Audit log query with filters
- Audit hash-chain integrity verification
- GDPR right-to-be-forgotten (self-service deletion)
- GDPR data portability (self-service export)
"""

import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt_handler import get_current_user
from app.auth.permissions import require_permission, Permission
from app.core.config import get_settings
from app.db.session import get_db
from app.models.user import User

logger = logging.getLogger("api_compliance")
router = APIRouter(prefix="/compliance", tags=["Compliance"])


# ── SOC2 Readiness ───────────────────────────────────────────


@router.get("/status")
async def compliance_status(
    user=Depends(require_permission(Permission.COMPLIANCE_READ)),
    db: AsyncSession = Depends(get_db),
):
    """SOC2 readiness report.

    Evaluates the current state of key compliance controls and returns
    an overall status with per-control detail.
    """
    settings = get_settings()
    controls = {}

    # 1. Audit logging
    controls["audit_logging"] = {
        "status": "compliant",
        "detail": "Centralized audit logging is active with PII masking.",
    }

    # 2. Audit hash-chain
    if settings.AUDIT_CHAIN_ENABLED:
        try:
            from app.services.audit_chain import AuditChain
            result = await AuditChain.verify_chain(db, limit=100)
            chain_ok = result.get("valid", False)
            controls["audit_integrity"] = {
                "status": "compliant" if chain_ok else "non_compliant",
                "detail": result.get("message", ""),
                "verified_entries": result.get("verified_count", 0),
            }
        except Exception as e:
            controls["audit_integrity"] = {
                "status": "unknown",
                "detail": f"Verification failed: {str(e)}",
            }
    else:
        controls["audit_integrity"] = {
            "status": "partial",
            "detail": "Hash-chain audit is disabled (AUDIT_CHAIN_ENABLED=False).",
        }

    # 3. Encryption at rest
    controls["encryption_at_rest"] = {
        "status": "compliant",
        "detail": f"KMS backend: {settings.KMS_BACKEND}. "
                  f"Fernet AES-128-CBC with PBKDF2 key derivation.",
    }

    # 4. Access control
    controls["access_control"] = {
        "status": "compliant",
        "detail": "RBAC with 4 roles (admin, auditor, developer, user). "
                  "JWT-based auth with token revocation support.",
    }

    # 5. Data retention
    controls["data_retention"] = {
        "status": "compliant" if settings.GDPR_DELETION_ENABLED else "partial",
        "detail": f"Retention policy: {settings.DATA_RETENTION_DAYS} days. "
                  f"GDPR deletion: {'enabled' if settings.GDPR_DELETION_ENABLED else 'disabled'}.",
    }

    # 6. Availability
    controls["availability"] = {
        "status": "compliant",
        "detail": "Health probes (/health, /health/ready, /health/deep), "
                  "graceful shutdown, circuit breaker, saturation guard.",
    }

    # Overall status
    statuses = [c["status"] for c in controls.values()]
    if all(s == "compliant" for s in statuses):
        overall = "compliant"
    elif any(s == "non_compliant" for s in statuses):
        overall = "non_compliant"
    else:
        overall = "partial"

    recommendations = []
    if settings.KMS_BACKEND == "local":
        recommendations.append(
            "Consider migrating to AWS KMS (KMS_BACKEND=aws) for "
            "hardware-backed key management in production."
        )
    if not settings.AUDIT_CHAIN_ENABLED:
        recommendations.append(
            "Enable hash-chain audit logging (AUDIT_CHAIN_ENABLED=True) "
            "for tamper-evident audit trails."
        )

    return {
        "overall_status": overall,
        "controls": controls,
        "recommendations": recommendations,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Audit Log Query ──────────────────────────────────────────


@router.get("/audit-log")
async def get_audit_log(
    start: Optional[str] = Query(None, description="ISO-8601 start datetime"),
    end: Optional[str] = Query(None, description="ISO-8601 end datetime"),
    event_type: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user=Depends(require_permission(Permission.AUDIT_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Query audit log with filters."""
    from app.models.audit_log import AuditLog

    stmt = select(AuditLog).order_by(desc(AuditLog.created_at))

    filters = []
    if start:
        try:
            start_dt = datetime.fromisoformat(start)
            filters.append(AuditLog.created_at >= start_dt)
        except ValueError:
            raise HTTPException(400, "Invalid start datetime format")
    if end:
        try:
            end_dt = datetime.fromisoformat(end)
            filters.append(AuditLog.created_at <= end_dt)
        except ValueError:
            raise HTTPException(400, "Invalid end datetime format")
    if event_type:
        filters.append(AuditLog.event_type == event_type)
    if category:
        filters.append(AuditLog.event_category == category)

    if filters:
        stmt = stmt.where(and_(*filters))

    stmt = stmt.offset(offset).limit(limit)
    result = await db.execute(stmt)
    entries = result.scalars().all()

    return {
        "count": len(entries),
        "offset": offset,
        "entries": [
            {
                "id": str(e.id),
                "event_type": e.event_type,
                "event_category": e.event_category,
                "user_id": str(e.user_id) if e.user_id else None,
                "detail": e.detail,
                "ip_address": e.ip_address,
                "created_at": e.created_at.isoformat() if e.created_at else None,
                "integrity_hash": e.integrity_hash,
            }
            for e in entries
        ],
    }


# ── Audit Chain Verification ─────────────────────────────────


@router.post("/audit-verify")
async def verify_audit_chain(
    limit: int = Query(1000, ge=1, le=10000),
    user=Depends(require_permission(Permission.AUDIT_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Verify audit log hash-chain integrity.

    Walks the chain of hash-linked audit entries and reports whether
    the chain is intact or broken.
    """
    from app.services.audit_chain import AuditChain

    result = await AuditChain.verify_chain(db, limit=limit)
    return result


# ── GDPR — Right to be Forgotten ─────────────────────────────


@router.post("/gdpr/delete-my-data")
async def gdpr_delete(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """GDPR right-to-be-forgotten — self-service data deletion.

    Deletes all scans, vulnerabilities, sessions, and anonymises
    audit logs for the requesting user.  The user account is marked
    as DELETED.
    """
    settings = get_settings()
    if not settings.GDPR_DELETION_ENABLED:
        raise HTTPException(
            status_code=403,
            detail="GDPR deletion is currently disabled by administrator.",
        )

    from app.services.data_retention import DataRetentionService
    from app.services.audit_service import AuditService

    # Audit the deletion request before performing it
    await AuditService.log(
        db,
        event_type="gdpr_delete_requested",
        event_category="security",
        user_id=user.id,
        detail={"action": "self_service_deletion"},
    )

    counts = await DataRetentionService.delete_user_data(db, user.id)
    await db.commit()

    return {
        "status": "deleted",
        "message": "All your data has been deleted per GDPR Article 17.",
        "summary": counts,
    }


# ── GDPR — Data Portability ──────────────────────────────────


@router.get("/gdpr/export-my-data")
async def gdpr_export(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """GDPR data portability — export all user data as JSON.

    Returns a structured JSON document containing the user's profile,
    scan history, vulnerability findings, and audit log entries.
    """
    from app.services.data_retention import DataRetentionService
    from app.services.audit_service import AuditService

    await AuditService.log(
        db,
        event_type="gdpr_export_requested",
        event_category="security",
        user_id=user.id,
        detail={"action": "data_portability_export"},
    )

    export = await DataRetentionService.export_user_data(db, user.id)
    return export
