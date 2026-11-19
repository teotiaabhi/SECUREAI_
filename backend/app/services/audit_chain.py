"""
SOC2-compliant hash-chain audit logging.

Each audit entry is linked to its predecessor via SHA-256 hashes,
forming a tamper-evident chain.  If any record is modified or deleted,
the chain verification will detect the break.

Usage:
    from app.services.audit_chain import AuditChain
    entry = await AuditChain.append(db, "login_success", "auth", user_id, detail, ip)
    result = await AuditChain.verify_chain(db, limit=5000)
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from uuid import UUID

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("audit_chain")

# Genesis hash — used for the very first entry in the chain.
GENESIS_HASH = "0" * 64


class AuditChain:
    """Immutable hash-chain audit log for SOC2 integrity verification."""

    @staticmethod
    def compute_hash(
        prev_hash: str,
        event_type: str,
        timestamp: str,
        detail_json: str,
    ) -> str:
        """Deterministic SHA-256 hash linking to the previous entry."""
        payload = f"{prev_hash}|{event_type}|{timestamp}|{detail_json}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    async def _get_last_hash(cls, db: AsyncSession) -> str:
        """Retrieve the integrity_hash of the most recent chain entry."""
        from app.models.audit_log import AuditLog

        stmt = (
            select(AuditLog.integrity_hash)
            .where(AuditLog.integrity_hash.isnot(None))
            .order_by(desc(AuditLog.created_at))
            .limit(1)
        )
        result = await db.execute(stmt)
        row = result.scalar_one_or_none()
        return row if row else GENESIS_HASH

    @classmethod
    async def append(
        cls,
        db: AsyncSession,
        event_type: str,
        event_category: str,
        user_id: Optional[UUID] = None,
        detail: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ):
        """Create a hash-chained audit log entry.

        Returns the AuditLog instance (not yet committed — caller controls
        the transaction boundary).
        """
        from app.models.audit_log import AuditLog

        prev_hash = await cls._get_last_hash(db)
        now = datetime.now(timezone.utc)
        timestamp_str = now.isoformat()
        detail_json = json.dumps(detail, sort_keys=True, default=str) if detail else "{}"

        integrity_hash = cls.compute_hash(prev_hash, event_type, timestamp_str, detail_json)

        entry = AuditLog(
            user_id=user_id,
            event_type=event_type,
            event_category=event_category,
            detail=detail,
            ip_address=ip_address,
            user_agent=user_agent[:512] if user_agent else None,
            integrity_hash=integrity_hash,
            prev_hash=prev_hash,
        )
        db.add(entry)
        return entry

    @classmethod
    async def verify_chain(
        cls,
        db: AsyncSession,
        start_id: Optional[UUID] = None,
        limit: int = 1000,
    ) -> Dict[str, Any]:
        """Walk the hash chain and verify each entry links correctly.

        Returns:
            {
                "valid": bool,
                "verified_count": int,
                "total_checked": int,
                "broken_at": str | None,  # ID of the first broken entry
                "message": str,
            }
        """
        from app.models.audit_log import AuditLog

        stmt = (
            select(AuditLog)
            .where(AuditLog.integrity_hash.isnot(None))
            .order_by(AuditLog.created_at)
            .limit(limit)
        )
        if start_id:
            # Start verification from a specific entry
            start_entry = await db.get(AuditLog, start_id)
            if start_entry and start_entry.created_at:
                stmt = stmt.where(AuditLog.created_at >= start_entry.created_at)

        result = await db.execute(stmt)
        entries = result.scalars().all()

        if not entries:
            return {
                "valid": True,
                "verified_count": 0,
                "total_checked": 0,
                "broken_at": None,
                "message": "No hash-chained entries found.",
            }

        verified = 0
        for i, entry in enumerate(entries):
            expected_prev = entries[i - 1].integrity_hash if i > 0 else GENESIS_HASH

            # Check that prev_hash matches the previous entry's integrity_hash
            if entry.prev_hash != expected_prev:
                return {
                    "valid": False,
                    "verified_count": verified,
                    "total_checked": i + 1,
                    "broken_at": str(entry.id),
                    "message": f"Chain broken at entry {entry.id}: "
                               f"prev_hash mismatch (expected {expected_prev[:12]}..., "
                               f"got {(entry.prev_hash or 'None')[:12]}...)",
                }

            # Recompute the hash and verify integrity
            detail_json = json.dumps(entry.detail, sort_keys=True, default=str) if entry.detail else "{}"
            timestamp_str = entry.created_at.isoformat() if entry.created_at else ""
            expected_hash = cls.compute_hash(
                entry.prev_hash or GENESIS_HASH,
                entry.event_type,
                timestamp_str,
                detail_json,
            )

            if entry.integrity_hash != expected_hash:
                return {
                    "valid": False,
                    "verified_count": verified,
                    "total_checked": i + 1,
                    "broken_at": str(entry.id),
                    "message": f"Chain broken at entry {entry.id}: "
                               f"integrity_hash tampered "
                               f"(expected {expected_hash[:12]}..., "
                               f"got {entry.integrity_hash[:12]}...)",
                }

            verified += 1

        return {
            "valid": True,
            "verified_count": verified,
            "total_checked": len(entries),
            "broken_at": None,
            "message": f"All {verified} entries verified successfully.",
        }
