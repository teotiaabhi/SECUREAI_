"""
AuditLog model — persistent audit trail for security events.
"""

import uuid
from sqlalchemy import Column, String, DateTime, func, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import ForeignKey
from app.db.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    event_type = Column(String(50), nullable=False, index=True)
    event_category = Column(String(20), nullable=False, index=True)
    detail = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    # SOC2 hash-chain integrity (nullable for backward compatibility)
    integrity_hash = Column(String(64), nullable=True, index=True)
    prev_hash = Column(String(64), nullable=True)

    def __repr__(self) -> str:
        return f"<AuditLog {self.event_type} user={self.user_id}>"
