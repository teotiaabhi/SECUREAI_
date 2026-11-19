"""
TokenBlacklist model — JWT token revocation via jti blacklist.
Expired entries are cleaned up periodically by the cleanup service.
"""

import uuid
from sqlalchemy import Column, String, DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from app.db.base import Base


class TokenBlacklist(Base):
    __tablename__ = "token_blacklist"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    jti = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    token_type = Column(String(10), nullable=False)  # "access" or "refresh"
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self) -> str:
        return f"<TokenBlacklist jti={self.jti[:8]}...>"
