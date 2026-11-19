"""
User model — maps to existing Supabase 'users' table.
Extended with role, status, tier, and resource tracking columns.
"""

import uuid
import enum as stdlib_enum
from datetime import datetime
from sqlalchemy import Column, String, DateTime, func, Integer, Date, Enum, Boolean, BigInteger
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.db.base import Base
from app.db.safe_model import SafeColumnMixin


class UserRole(str, stdlib_enum.Enum):
    USER = "user"


class UserStatus(str, stdlib_enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class UserTier(str, stdlib_enum.Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class User(Base, SafeColumnMixin):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(320), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    provider = Column(String(20), nullable=False)  # google / github
    avatar_url = Column(String(512), nullable=True)
    google_id = Column(String(64), nullable=True, index=True)
    github_token_encrypted = Column(String(1024), nullable=True)

    # Security & tenant fields
    role = Column(
        Enum(UserRole, name="user_role", create_constraint=True,
             values_callable=lambda x: [e.value for e in x]),
        default=UserRole.USER, server_default="user", nullable=False,
    )
    status = Column(
        Enum(UserStatus, name="user_status", create_constraint=True,
             values_callable=lambda x: [e.value for e in x]),
        default=UserStatus.ACTIVE, server_default="active", nullable=False,
    )
    tier = Column(
        Enum(UserTier, name="user_tier", create_constraint=True,
             values_callable=lambda x: [e.value for e in x]),
        default=UserTier.FREE, server_default="free", nullable=False,
    )
    is_paid = Column(Boolean, default=False, server_default="false", nullable=False)

    # Resource tracking
    ai_tokens_used = Column(Integer, default=0, server_default="0", nullable=False)
    scans_today = Column(Integer, default=0, server_default="0", nullable=False)
    last_scan_reset = Column(Date, nullable=True)
    storage_used_bytes = Column(BigInteger, default=0, server_default="0", nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<User {self.email}>"
