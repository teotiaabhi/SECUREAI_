"""
Centralized audit logging service.

Writes structured audit events to both:
- Database (audit_logs table) for persistence and querying
- Structlog for real-time log aggregation

Includes PII masking for emails and IP addresses.

Event categories:
- auth: login_success, login_failed, token_refreshed, token_revoked
- scan: scan_started, scan_completed, scan_failed, scan_cancelled
- security: rate_limited, suspicious_activity, file_rejected
- admin: user_suspended, config_changed
"""

import re
import logging
from typing import Optional, Dict, Any
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("audit")

EMAIL_PATTERN = re.compile(
    r"([a-zA-Z0-9])[a-zA-Z0-9._%+-]*@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
)


def mask_email(email: str) -> str:
    """Mask email: john.doe@example.com -> j***@example.com"""
    if not email:
        return "***"
    match = EMAIL_PATTERN.match(email)
    if match:
        return f"{match.group(1)}***@{match.group(2)}"
    return "***@***"


def mask_ip(ip: str) -> str:
    """Mask last octet: 192.168.1.100 -> 192.168.1.***"""
    if not ip:
        return "***"
    parts = ip.rsplit(".", 1)
    if len(parts) == 2:
        return f"{parts[0]}.***"
    # IPv6 or unusual format
    return ip[:len(ip) // 2] + "***"


def _mask_pii(detail: Dict[str, Any]) -> Dict[str, Any]:
    """Deep-mask PII fields in a detail dictionary."""
    if not detail:
        return detail

    masked = {}
    pii_keys = {"email", "user_email", "recipient_email"}
    ip_keys = {"ip", "ip_address", "remote_addr", "client_ip"}

    for k, v in detail.items():
        if k in pii_keys and isinstance(v, str):
            masked[k] = mask_email(v)
        elif k in ip_keys and isinstance(v, str):
            masked[k] = mask_ip(v)
        elif isinstance(v, dict):
            masked[k] = _mask_pii(v)
        else:
            masked[k] = v
    return masked


class AuditService:
    """Write structured audit events to DB and structured logs."""

    @staticmethod
    async def log(
        db: AsyncSession,
        event_type: str,
        event_category: str,
        user_id: Optional[UUID] = None,
        detail: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        """Record an audit event.

        Args:
            db: Database session.
            event_type: Event name (e.g., "login_success", "scan_started").
            event_category: Category ("auth", "scan", "security", "admin").
            user_id: The user who triggered the event (nullable for unauthenticated).
            detail: Additional context as a dict (will be PII-masked).
            ip_address: Client IP address (will be masked in logs).
            user_agent: Client user agent string (truncated to 512 chars).
        """
        from app.models.audit_log import AuditLog

        # Mask PII in detail
        safe_detail = _mask_pii(detail) if detail else None
        masked_ip = mask_ip(ip_address) if ip_address else None

        # Write to DB — delegate to hash-chain when enabled
        try:
            _use_chain = False
            try:
                from app.core.config import get_settings as _get_settings
                _use_chain = getattr(_get_settings(), "AUDIT_CHAIN_ENABLED", False)
            except Exception:
                pass

            if _use_chain:
                from app.services.audit_chain import AuditChain
                entry = await AuditChain.append(
                    db,
                    event_type=event_type,
                    event_category=event_category,
                    user_id=user_id,
                    detail=safe_detail,
                    ip_address=masked_ip,
                    user_agent=user_agent[:512] if user_agent else None,
                )
            else:
                entry = AuditLog(
                    user_id=user_id,
                    event_type=event_type,
                    event_category=event_category,
                    detail=safe_detail,
                    ip_address=masked_ip,
                    user_agent=user_agent[:512] if user_agent else None,
                )
                db.add(entry)
            # Don't flush here — let the caller's transaction handle it
        except Exception as e:
            logger.error("audit_db_write_failed: %s", str(e))

        # Also emit structured log
        logger.info(
            "audit_event",
            extra={
                "event_type": event_type,
                "category": event_category,
                "user_id": str(user_id) if user_id else None,
                "detail": safe_detail,
                "ip": masked_ip,
            },
        )

    @staticmethod
    async def log_no_db(
        event_type: str,
        event_category: str,
        user_id: Optional[UUID] = None,
        detail: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Log audit event to structlog only (when no DB session is available)."""
        safe_detail = _mask_pii(detail) if detail else None
        masked_ip = mask_ip(ip_address) if ip_address else None

        logger.info(
            "audit_event",
            extra={
                "event_type": event_type,
                "category": event_category,
                "user_id": str(user_id) if user_id else None,
                "detail": safe_detail,
                "ip": masked_ip,
            },
        )
