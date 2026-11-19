"""
Orchestration-layer database models: ScanSessionRecord, ScanProgress, ScanFile.
"""

import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, DateTime, ForeignKey,
    func, JSON, Text, BigInteger,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.db.base import Base


class ScanSessionRecord(Base):
    """Orchestration metadata for a scan session."""
    __tablename__ = "scan_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True,
    )
    phase = Column(String(30), default="queued", nullable=False, index=True)
    priority = Column(Integer, default=10)
    temp_dir = Column(String(512), nullable=True)
    source_type = Column(String(30), nullable=True)
    repo_url = Column(String(1024), nullable=True)
    branch = Column(String(255), nullable=True)
    clone_size_bytes = Column(BigInteger, nullable=True)
    phase_started_at = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)

    scan = relationship("Scan", backref="session")


class ScanProgress(Base):
    """Real-time progress tracking persisted to DB (survives server restart)."""
    __tablename__ = "scan_progress"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True,
    )
    phase = Column(String(30), default="queued")
    percent = Column(Float, default=0.0)
    current_file = Column(String(512), default="")
    live_vuln_count = Column(Integer, default=0)
    files_scanned = Column(Integer, default=0)
    total_files = Column(Integer, default=0)
    eta_seconds = Column(Float, default=0.0)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(),
    )

    scan = relationship("Scan", backref="progress")


class ScanFile(Base):
    """Per-file tracking within a scan."""
    __tablename__ = "scan_files"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    file_path = Column(String(1024), nullable=False)
    file_name = Column(String(512), nullable=False)
    language = Column(String(50), nullable=True)
    size_bytes = Column(Integer, default=0)
    priority = Column(Integer, default=2)
    category = Column(String(50), nullable=True)
    status = Column(String(20), default="pending")
    finding_count = Column(Integer, default=0)
    scan_duration_ms = Column(Integer, default=0)
    error_message = Column(String(512), nullable=True)

    scan = relationship("Scan", backref="files")
