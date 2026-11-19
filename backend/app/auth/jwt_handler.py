"""
JWT token handling — creation, decoding, revocation, and user authentication.

Security features:
- JTI (JWT ID) claim for token revocation
- Token blacklist checking
- User status validation (suspended/deleted users blocked)
- Tenant context injection for RLS
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4, UUID

from jose import jwt, JWTError
from app.core.logging import get_logger

logger = get_logger("jwt_handler")
from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import get_settings
from app.db.session import get_db
from app.models.user import User, UserStatus
from app.middleware.tenant_context import set_current_user_id

security_scheme = HTTPBearer(auto_error=False)


def create_access_token(user_id: str, email: str, role: str = "developer") -> str:
    settings = get_settings()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": expire,
        "type": "access",
        "jti": str(uuid4()),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    settings = get_settings()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": user_id,
        "exp": expire,
        "type": "refresh",
        "jti": str(uuid4()),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def is_token_revoked(jti: str, db: AsyncSession) -> bool:
    """Check if a token JTI has been revoked (blacklisted)."""
    if not jti:
        return False
    from app.models.token_blacklist import TokenBlacklist
    result = await db.execute(
        select(TokenBlacklist).where(TokenBlacklist.jti == jti)
    )
    return result.scalar_one_or_none() is not None


async def revoke_token(
    jti: str,
    user_id: UUID,
    token_type: str,
    expires_at: datetime,
    db: AsyncSession,
) -> None:
    """Add a token JTI to the blacklist."""
    from app.models.token_blacklist import TokenBlacklist
    # Skip if already revoked — prevents UniqueViolation / PendingRollbackError
    existing = await db.execute(
        select(TokenBlacklist.id).where(TokenBlacklist.jti == jti)
    )
    if existing.scalar_one_or_none() is not None:
        return
    entry = TokenBlacklist(
        jti=jti,
        user_id=user_id,
        token_type=token_type,
        expires_at=expires_at,
    )
    db.add(entry)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    # Try Bearer token first
    token = None
    auth_method = "none"
    if credentials:
        token = credentials.credentials
        auth_method = "bearer"
    else:
        # Try cookie
        token = request.cookies.get("access_token")
        if token:
            auth_method = "cookie"

    if not token:
        logger.debug("auth_no_token", path=request.url.path, method=request.method)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    payload = decode_token(token)

    # Log decoded payload (never the raw token)
    logger.debug(
        "auth_token_decoded",
        auth_method=auth_method,
        sub=payload.get("sub"),
        email=payload.get("email"),
        role=payload.get("role"),
        token_type=payload.get("type"),
        jti=payload.get("jti"),
        exp=payload.get("exp"),
    )

    if payload.get("type") != "access":
        logger.warning("auth_invalid_token_type", token_type=payload.get("type"))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    user_id = payload.get("sub")
    if not user_id:
        logger.warning("auth_missing_sub")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    # Check if token has been revoked
    jti = payload.get("jti")
    if jti and await is_token_revoked(jti, db):
        logger.warning("auth_token_revoked", jti=jti, user_id=user_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        logger.warning("auth_user_not_found", user_id=user_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # Check user status — suspended or deleted users cannot access the API
    if user.status != UserStatus.ACTIVE:
        logger.warning("auth_user_inactive", user_id=user_id, status=str(user.status))
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended or deactivated",
        )

    # Set tenant context for RLS
    set_current_user_id(str(user.id))

    logger.debug("auth_success", user_id=str(user.id), email=user.email, role=str(user.role))
    return user
