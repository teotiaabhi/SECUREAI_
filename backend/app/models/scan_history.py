"""
ScanHistory model — tracks per-scan resource consumption for
quota enforcement and billing analytics.
"""

import uuid
from datetime import datetime
from sqlalchemy import Column, Integer, Float, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID
from app.db.base import Base


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_time = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    tokens_used = Column(Integer, default=0, nullable=False)
    files_scanned = Column(Integer, default=0, nullable=False)
    duration = Column(Float, default=0.0, nullable=False)
