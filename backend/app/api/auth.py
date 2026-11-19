"""
Auth API Routes — hardened with secure cookies, token revocation, and audit logging.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, Field

from app.db.session import get_db
from app.schemas.auth import GoogleAuthRequest, GitHubAuthRequest, TokenResponse, UserResponse
from app.auth.jwt_handler import (
    create_access_token, create_refresh_token, decode_token,
    get_current_user, revoke_token,
)
from app.auth.oauth_google import (
    build_google_auth_url,
    exchange_google_code,
    get_google_user_info,
    verify_google_token,
    get_or_create_google_user,
)
from app.auth.oauth_github import (
    build_github_auth_url,
    exchange_github_code,
    get_github_user_info,
    get_or_create_github_user,
)
from app.models.user import User, UserStatus
from app.services.audit_service import AuditService
from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger("api_auth")
router = APIRouter(prefix="/auth", tags=["Authentication"])


def _cookie_secure() -> bool:
    """Return True if cookies should have Secure flag (production)."""
    settings = get_settings()
    return not settings.DEBUG


# ── Profile Update Schema ────────────────────────────────────────

class ProfileUpdateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Display name")


# ── Google OAuth (Server-Side Authorization Code Flow) ──────────


@router.get("/google")
async def google_login_redirect():
    """Redirect the user's browser to Google's OAuth consent screen."""
    auth_url = build_google_auth_url()
    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/google/callback")
async def google_callback(
    request: Request,
    code: str | None = None,
    error: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Handle Google's OAuth callback.
    Exchanges the authorization code for tokens, fetches user profile,
    creates/finds user, sets JWT in httpOnly cookie, redirects to frontend.
    """
    settings = get_settings()
    frontend_url = settings.CORS_ORIGINS[0] if settings.CORS_ORIGINS else "http://localhost:3000"
    client_ip = request.client.host if request.client else None

    if error:
        logger.warning("google_oauth_error", error=error)
        await AuditService.log(
            db, "login_failed", "auth",
            detail={"provider": "google", "reason": error},
            ip_address=client_ip,
        )
        await db.commit()
        return RedirectResponse(
            url=f"{frontend_url}/login?error=google_denied",
            status_code=302,
        )

    if not code:
        logger.warning("google_oauth_no_code")
        return RedirectResponse(
            url=f"{frontend_url}/login?error=missing_code",
            status_code=302,
        )

    try:
        # 1. Exchange authorization code for tokens
        token_data = await exchange_google_code(code)
        access_token = token_data["access_token"]

        # 2. Fetch real Google profile data
        user_info = await get_google_user_info(access_token)

        # 3. Create or update user in database
        user = await get_or_create_google_user(db, user_info)
        await db.commit()

        # 4. Generate JWT
        jwt_access = create_access_token(str(user.id), user.email, user.role.value)
        jwt_refresh = create_refresh_token(str(user.id))

        # 5. Audit event
        await AuditService.log(
            db, "login_success", "auth",
            user_id=user.id,
            detail={"provider": "google", "email": user.email},
            ip_address=client_ip,
        )
        await db.commit()

        # 6. Redirect to frontend callback with tokens (avoids cross-origin cookie issues)
        from urllib.parse import urlencode
        callback_params = urlencode({"token": jwt_access, "refresh": jwt_refresh})
        redirect_url = f"{frontend_url}/auth/callback?{callback_params}"
        response = RedirectResponse(url=redirect_url, status_code=302)

        # Also set httpOnly cookies as fallback (works when same-origin / proxied)
        response.set_cookie(
            key="access_token",
            value=jwt_access,
            httponly=True,
            secure=_cookie_secure(),
            samesite="lax",
            max_age=1800,
            path="/",
        )
        response.set_cookie(
            key="refresh_token",
            value=jwt_refresh,
            httponly=True,
            secure=_cookie_secure(),
            samesite="lax",
            max_age=604800,  # 7 days
            path="/",
        )

        logger.info("google_oauth_success", email=user.email)
        return response

    except ValueError as e:
        logger.error("google_oauth_exchange_failed", error=str(e))
        await AuditService.log(
            db, "login_failed", "auth",
            detail={"provider": "google", "reason": str(e)},
            ip_address=client_ip,
        )
        await db.commit()
        return RedirectResponse(
            url=f"{frontend_url}/login?error=auth_failed",
            status_code=302,
        )
    except Exception as e:
        logger.error("google_oauth_unexpected_error", error=str(e))
        return RedirectResponse(
            url=f"{frontend_url}/login?error=server_error",
            status_code=302,
        )


# ── Google OAuth (Legacy ID Token Flow — backward compat) ──────


@router.post("/google", response_model=TokenResponse)
async def google_login_token(body: GoogleAuthRequest, response: Response, db: AsyncSession = Depends(get_db)):
    """Authenticate via Google OAuth ID token (legacy frontend-initiated flow)."""
    try:
        user_info = await verify_google_token(body.token)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    user = await get_or_create_google_user(db, user_info)
    await db.commit()

    access = create_access_token(str(user.id), user.email, user.role.value)
    refresh = create_refresh_token(str(user.id))

    response.set_cookie(
        key="access_token", value=access, httponly=True,
        secure=_cookie_secure(), samesite="lax", max_age=1800, path="/",
    )

    return TokenResponse(
        access_token=access, refresh_token=refresh,
        expires_in=1800,
    )


# ── GitHub OAuth (Server-Side Authorization Code Flow) ──────────


@router.get("/github")
async def github_login_redirect():
    """Redirect the user's browser to GitHub's OAuth consent screen."""
    auth_url = build_github_auth_url()
    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/github/callback")
async def github_callback(
    request: Request,
    code: str | None = None,
    error: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Handle GitHub's OAuth callback.
    Exchanges the authorization code for access token, fetches user profile,
    creates/finds user, stores encrypted GitHub token, sets JWT in httpOnly cookie,
    redirects to frontend dashboard.
    """
    settings = get_settings()
    frontend_url = settings.CORS_ORIGINS[0] if settings.CORS_ORIGINS else "http://localhost:3000"
    client_ip = request.client.host if request.client else None

    if error:
        logger.warning("github_oauth_error", error=error)
        await AuditService.log(
            db, "login_failed", "auth",
            detail={"provider": "github", "reason": error},
            ip_address=client_ip,
        )
        await db.commit()
        return RedirectResponse(
            url=f"{frontend_url}/login?error=github_denied",
            status_code=302,
        )

    if not code:
        logger.warning("github_oauth_no_code")
        return RedirectResponse(
            url=f"{frontend_url}/login?error=missing_code",
            status_code=302,
        )

    try:
        # 1. Exchange authorization code for GitHub access token
        token_data = await exchange_github_code(code)
        gh_access_token = token_data["access_token"]

        # 2. Fetch real GitHub profile data (email, name, avatar, login)
        user_info = await get_github_user_info(gh_access_token)

        # 3. Create or update user in database + store encrypted GitHub token
        user = await get_or_create_github_user(db, user_info, gh_access_token)
        await db.commit()

        # 4. Generate JWT
        jwt_access = create_access_token(str(user.id), user.email, user.role.value)
        jwt_refresh = create_refresh_token(str(user.id))

        # 5. Audit event
        await AuditService.log(
            db, "login_success", "auth",
            user_id=user.id,
            detail={"provider": "github", "email": user.email},
            ip_address=client_ip,
        )
        await db.commit()

        # 6. Redirect to frontend callback with tokens (avoids cross-origin cookie issues)
        from urllib.parse import urlencode
        callback_params = urlencode({"token": jwt_access, "refresh": jwt_refresh})
        redirect_url = f"{frontend_url}/auth/callback?{callback_params}"
        response = RedirectResponse(url=redirect_url, status_code=302)

        # Also set httpOnly cookies as fallback (works when same-origin / proxied)
        response.set_cookie(
            key="access_token",
            value=jwt_access,
            httponly=True,
            secure=_cookie_secure(),
            samesite="lax",
            max_age=1800,
            path="/",
        )
        response.set_cookie(
            key="refresh_token",
            value=jwt_refresh,
            httponly=True,
            secure=_cookie_secure(),
            samesite="lax",
            max_age=604800,  # 7 days
            path="/",
        )

        logger.info("github_oauth_success", email=user.email)
        return response

    except ValueError as e:
        logger.error("github_oauth_exchange_failed", error=str(e))
        await AuditService.log(
            db, "login_failed", "auth",
            detail={"provider": "github", "reason": str(e)},
            ip_address=client_ip,
        )
        await db.commit()
        return RedirectResponse(
            url=f"{frontend_url}/login?error=auth_failed",
            status_code=302,
        )
    except Exception as e:
        logger.error("github_oauth_unexpected_error", error=str(e))
        return RedirectResponse(
            url=f"{frontend_url}/login?error=server_error",
            status_code=302,
        )


# ── GitHub OAuth (Legacy POST Flow — backward compat) ──────────


@router.post("/github", response_model=TokenResponse)
async def github_login_post(body: GitHubAuthRequest, response: Response, db: AsyncSession = Depends(get_db)):
    """Authenticate via GitHub OAuth authorization code (legacy frontend-initiated flow)."""
    try:
        token_data = await exchange_github_code(body.code)
        access_token = token_data["access_token"]
        user_info = await get_github_user_info(access_token)
    except Exception as e:
        logger.error("github_auth_failed", error=str(e))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="GitHub authentication failed")

    user = await get_or_create_github_user(db, user_info, access_token)
    await db.commit()

    access = create_access_token(str(user.id), user.email, user.role.value)
    refresh = create_refresh_token(str(user.id))

    response.set_cookie(
        key="access_token", value=access, httponly=True,
        secure=_cookie_secure(), samesite="lax", max_age=1800, path="/",
    )

    return TokenResponse(
        access_token=access, refresh_token=refresh,
        expires_in=1800,
    )


# ── Session ─────────────────────────────────────────────────────


@router.get("/me", response_model=UserResponse)
async def get_me(user: User = Depends(get_current_user)):
    """Get current authenticated user."""
    return UserResponse.model_validate(user, from_attributes=True).model_copy(
        update={"github_connected": bool(user.github_token_encrypted)}
    )


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke tokens and clear authentication cookies."""
    # Revoke access token
    access_cookie = request.cookies.get("access_token")
    if access_cookie:
        try:
            payload = decode_token(access_cookie)
            jti = payload.get("jti")
            if jti:
                expires = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
                await revoke_token(jti, user.id, "access", expires, db)
        except Exception:
            pass  # Token may already be invalid

    # Revoke refresh token
    refresh_cookie = request.cookies.get("refresh_token")
    if refresh_cookie:
        try:
            payload = decode_token(refresh_cookie)
            jti = payload.get("jti")
            if jti:
                expires = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
                await revoke_token(jti, user.id, "refresh", expires, db)
        except Exception:
            pass

    await AuditService.log(
        db, "token_revoked", "auth",
        user_id=user.id,
        detail={"action": "logout"},
        ip_address=request.client.host if request.client else None,
    )
    try:
        await db.commit()
    except Exception:
        await db.rollback()

    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"message": "Logged out"}


@router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    refresh_token: str | None = None,
):
    """Refresh access token using refresh token. Revokes old refresh token.
    Accepts refresh_token from body/query OR from cookie."""
    # Try body/query param first, then fall back to cookie
    token = refresh_token or request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token provided",
        )
    payload = decode_token(token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # Check user status
    if user.status != UserStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended or deactivated",
        )

    # Revoke the old refresh token
    old_jti = payload.get("jti")
    if old_jti:
        old_expires = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        await revoke_token(old_jti, user.id, "refresh", old_expires, db)

    # Generate new tokens
    access = create_access_token(str(user.id), user.email, user.role.value)
    refresh = create_refresh_token(str(user.id))

    await AuditService.log(
        db, "token_refreshed", "auth",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
    )

    response.set_cookie(
        key="access_token", value=access, httponly=True,
        secure=_cookie_secure(), samesite="lax", max_age=1800, path="/",
    )
    response.set_cookie(
        key="refresh_token", value=refresh, httponly=True,
        secure=_cookie_secure(), samesite="lax", max_age=604800, path="/",
    )

    return TokenResponse(access_token=access, refresh_token=refresh, expires_in=1800)


# ── Profile Update ──────────────────────────────────────────────


@router.put("/user/update", response_model=UserResponse)
async def update_profile(
    body: ProfileUpdateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update current user's profile (name only)."""
    # Sanitize input
    clean_name = body.name.strip()
    if not clean_name:
        raise HTTPException(status_code=400, detail="Name cannot be empty")
    if len(clean_name) > 100:
        raise HTTPException(status_code=400, detail="Name too long")

    user.name = clean_name
    await db.flush()
    await db.commit()
    await db.refresh(user)

    logger.info("profile_updated", user_id=str(user.id), name=clean_name)
    return user


@router.get("/user/stats")
async def get_user_stats(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get user account statistics."""
    from sqlalchemy import func
    from app.models.scan import Scan

    result = await db.execute(
        select(func.count(Scan.id)).where(Scan.user_id == user.id)
    )
    total_scans = result.scalar() or 0

    return {
        "total_scans": total_scans,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }
