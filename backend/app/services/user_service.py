"""
User sync service — handles OAuth user creation/lookup against Supabase.
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.user import User
from app.core.logging import get_logger

logger = get_logger("user_service")


async def sync_user_after_oauth(
    db: AsyncSession,
    *,
    email: str,
    name: str,
    provider: str,
    avatar_url: str | None = None,
    google_id: str | None = None,
    github_token_encrypted: str | None = None,
) -> User:
    """
    After OAuth login: find existing user by email, or create a new one.
    Never creates duplicates — uses email as the unique key.
    Returns the User ORM object.
    """

    # 1. Query existing user
    result = await db.execute(
        select(User).where(User.email == email)
    )
    user = result.scalar_one_or_none()

    if user:
        # Update profile fields on each login
        user.name = name
        user.avatar_url = avatar_url
        if google_id and not user.google_id:
            user.google_id = google_id
        if github_token_encrypted:
            user.github_token_encrypted = github_token_encrypted
        logger.info("user_synced_existing", email=email, provider=provider)
    else:
        # Create new user record
        user = User(
            email=email,
            name=name,
            provider=provider,
            avatar_url=avatar_url,
            google_id=google_id,
            github_token_encrypted=github_token_encrypted,
        )
        db.add(user)
        logger.info("user_synced_new", email=email, provider=provider)

    await db.flush()  # Assign ID without full commit (caller controls transaction)
    return user


async def get_user_by_id(db: AsyncSession, user_id: str) -> User | None:
    """Fetch a single user by UUID. Returns None if not found."""
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    return result.scalar_one_or_none()
