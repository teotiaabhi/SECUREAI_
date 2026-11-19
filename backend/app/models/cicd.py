"""
CI/CD Integration models — Repository, Commit, BaselineFinding, VulnerabilityDelta.

Supports incremental diff scanning, vulnerability baselines, and delta tracking
for GitHub webhook-driven CI/CD pipelines.
"""

import uuid
import enum
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, ForeignKey,
    func, JSON, BigInteger, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.db.base import Base


class ScanMode(str, enum.Enum):
    FULL = "full"
    DIFF = "diff"
    FILE_ONLY = "file_only"


class WebhookDelivery(Base):
    """Tracks processed GitHub webhook delivery IDs for replay protection.

    Persisted to DB so replay protection survives server restarts.
    Old entries are periodically pruned via cleanup_service.
    """
    __tablename__ = "webhook_deliveries"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    delivery_id = Column(String(64), nullable=False, unique=True, index=True)
    event_type = Column(String(50), default="")
    repository_id = Column(
        UUID(as_uuid=True),
        ForeignKey("repositories.id", ondelete="CASCADE"),
        nullable=True, index=True,
    )
    received_at = Column(DateTime(timezone=True), server_default=func.now())


class Repository(Base):
    """GitHub repository connected for CI/CD scanning."""
    __tablename__ = "repositories"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    github_repo_id = Column(BigInteger, unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=False)
    default_branch = Column(String(100), default="main")
    webhook_secret = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    scan_config = Column(JSON, default=dict)
    installed_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(),
    )

    user = relationship("User", backref="repositories")
    commits = relationship("Commit", back_populates="repository", cascade="all, delete-orphan")
    baseline_findings = relationship(
        "BaselineFinding", back_populates="repository", cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Repository {self.full_name} (id={self.id})>"


class Commit(Base):
    """Git commit associated with a scan."""
    __tablename__ = "commits"
    __table_args__ = (
        UniqueConstraint("repository_id", "sha", name="uq_commits_repo_sha"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    repository_id = Column(
        UUID(as_uuid=True),
        ForeignKey("repositories.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True, index=True,
    )
    sha = Column(String(40), nullable=False, index=True)
    message = Column(String(512), default="")
    author = Column(String(255), default="")
    branch = Column(String(255), default="")
    pr_number = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    repository = relationship("Repository", back_populates="commits")
    scan = relationship("Scan", foreign_keys=[scan_id])

    def __repr__(self) -> str:
        return f"<Commit {self.sha[:8]} repo={self.repository_id}>"


class BaselineFinding(Base):
    """Vulnerability fingerprint stored as part of a repository baseline."""
    __tablename__ = "baseline_findings"
    __table_args__ = (
        UniqueConstraint(
            "repository_id", "detection_id", name="uq_baseline_repo_detection",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    repository_id = Column(
        UUID(as_uuid=True),
        ForeignKey("repositories.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
    )
    detection_id = Column(String(64), nullable=False, index=True)
    file_name = Column(String(512), nullable=False)
    vulnerability_type = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False)
    line_reference = Column(Integer, default=0)
    commit_sha = Column(String(40), default="")
    is_active = Column(Boolean, default=True, index=True)
    first_seen_at = Column(DateTime(timezone=True), server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), server_default=func.now())

    repository = relationship("Repository", back_populates="baseline_findings")

    def __repr__(self) -> str:
        return f"<BaselineFinding {self.detection_id[:12]} [{self.severity}]>"


class VulnerabilityDelta(Base):
    """Delta between a scan's findings and a baseline."""
    __tablename__ = "vulnerability_deltas"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True,
    )
    baseline_scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
    )
    new_count = Column(Integer, default=0)
    fixed_count = Column(Integer, default=0)
    unchanged_count = Column(Integer, default=0)
    regression_detected = Column(Boolean, default=False)
    delta_detail = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", foreign_keys=[scan_id], backref="delta")

    def __repr__(self) -> str:
        return (
            f"<VulnerabilityDelta scan={self.scan_id} "
            f"new={self.new_count} fixed={self.fixed_count}>"
        )
