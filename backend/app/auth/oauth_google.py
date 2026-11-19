import httpx
from urllib.parse import urlencode
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.user import User

logger = get_logger("oauth_google")

GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"


def build_google_auth_url() -> str:
    """Build the Google OAuth authorization URL that initiates the consent screen."""
    settings = get_settings()
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


async def exchange_google_code(code: str) -> dict:
    """Exchange authorization code for access + id tokens via Google's token endpoint."""
    settings = get_settings()
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        if resp.status_code != 200:
            error_detail = resp.json().get("error_description", resp.text)
            logger.error("google_token_exchange_failed", status=resp.status_code, detail=error_detail)
            raise ValueError(f"Google token exchange failed: {error_detail}")

        data = resp.json()
        if "access_token" not in data:
            raise ValueError("No access_token in Google response")
        return data


async def get_google_user_info(access_token: str) -> dict:
    """Fetch the authenticated user's Google profile using the access token."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        if resp.status_code != 200:
            raise ValueError("Failed to fetch Google user info")

        data = resp.json()
        return {
            "google_id": data.get("id"),
            "email": data.get("email"),
            "name": data.get("name", data.get("email", "").split("@")[0]),
            "avatar_url": data.get("picture"),
        }


async def verify_google_token(id_token: str) -> dict:
    """Verify a Google OAuth ID token and return user info (legacy / backward compat)."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}",
            timeout=10,
        )
        if resp.status_code != 200:
            raise ValueError("Invalid Google token")
        data = resp.json()

        settings = get_settings()
        if settings.GOOGLE_CLIENT_ID and data.get("aud") != settings.GOOGLE_CLIENT_ID:
            raise ValueError("Token audience mismatch")

        return {
            "google_id": data.get("sub"),
            "email": data["email"],
            "name": data.get("name", data["email"].split("@")[0]),
            "avatar_url": data.get("picture"),
        }


async def get_or_create_google_user(db: AsyncSession, user_info: dict) -> User:
    """Find existing user by google_id or email, or create a new one from Google OAuth."""
    user = None

    # Try matching by google_id first (most reliable)
    google_id = user_info.get("google_id")
    if google_id:
        result = await db.execute(
            select(User).where(User.google_id == google_id)
        )
        user = result.scalar_one_or_none()

    # Fallback to email match
    if not user:
        result = await db.execute(
            select(User).where(User.email == user_info["email"])
        )
        user = result.scalar_one_or_none()

    if user:
        # Update profile on each login
        user.name = user_info["name"]
        user.avatar_url = user_info.get("avatar_url")
        if google_id and not user.google_id:
            user.google_id = google_id
        logger.info("google_login_existing", email=user_info["email"])
    else:
        user = User(
            email=user_info["email"],
            name=user_info["name"],
            provider="google",
            avatar_url=user_info.get("avatar_url"),
            google_id=google_id,
        )
        db.add(user)
        logger.info("google_login_new", email=user_info["email"])

    await db.flush()
    return user
