"""
Scan model — maps to existing Supabase 'scans' table.
"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, func, JSON, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.db.base import Base
import enum


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    QUEUED = "queued"
    CLONING = "cloning"
    UPLOADING = "uploading"
    EXTRACTING = "extracting"
    CLASSIFYING = "classifying"
    ANALYZING = "analyzing"
    SCANNING = "scanning"
    AI_REASONING = "ai_reasoning"
    AI_VALIDATING = "ai_validating"
    GENERATING_REPORT = "generating_report"
    REPORTING = "reporting"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    repo_name = Column(String(255), nullable=False)
    status = Column(String(30), default=ScanStatus.PENDING, nullable=False, index=True)
    total_files = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    security_score = Column(Float, default=0.0)
    confidence_score = Column(Float, default=0.0)
    grade = Column(String(2), default="")
    config = Column(JSON, default=dict)
    duration = Column(Float, default=0.0)
    error_message = Column(String(1024), nullable=True)
    report_data = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # CI/CD fields (nullable for backwards compat with existing scans)
    scan_mode = Column(String(20), default="full")
    repository_id = Column(
        UUID(as_uuid=True),
        ForeignKey("repositories.id", ondelete="SET NULL"),
        nullable=True, index=True,
    )
    base_commit_sha = Column(String(40), nullable=True)
    head_commit_sha = Column(String(40), nullable=True)
    pr_number = Column(Integer, nullable=True)

    user = relationship("User", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    chunks = relationship("ScanChunk", back_populates="scan", cascade="all, delete-orphan")
    repository = relationship("Repository", foreign_keys=[repository_id])

    def __repr__(self) -> str:
        return f"<Scan {self.id} repo={self.repo_name} status={self.status}>"
