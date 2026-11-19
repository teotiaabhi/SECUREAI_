"""
Database session layer — production-ready async PostgreSQL via Supabase Session Pooler.

Key pgBouncer compatibility notes:
- statement_cache_size=0: pgBouncer does not support prepared statements
- ssl="require": Supabase requires SSL for all connections
- pool_pre_ping=True: detect stale connections before use

Security:
- SSL cert verification enabled in production (CERT_REQUIRED)
- RLS tenant context injected per transaction via SET LOCAL
"""

import ssl
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import text
from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger("db")
settings = get_settings()

# ── SSL context for Supabase ────────────────────────────────────
ssl_context = ssl.create_default_context()
if settings.DEBUG:
    # Dev only — disable cert verification for local/tunneled Supabase
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
# else: defaults are CERT_REQUIRED + check_hostname=True

# ── Engine ──────────────────────────────────────────────────────
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DB_ECHO,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=300,
    pool_timeout=30,
    connect_args={
        "ssl": ssl_context,                    # Required by Supabase
        "statement_cache_size": 0,             # pgBouncer: disable prepared statement cache
        "prepared_statement_name_func": lambda: "",  # pgBouncer: use unnamed (anonymous) statements
    },
)

# ── Session factory ─────────────────────────────────────────────
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ── Dependency ──────────────────────────────────────────────────
async def get_db() -> AsyncSession:
    """FastAPI dependency that yields an async database session.

    Injects RLS tenant context (SET LOCAL app.current_user_id) if a user
    is authenticated in the current request context.
    """
    from app.middleware.tenant_context import get_current_user_id

    async with async_session_factory() as session:
        try:
            # Inject RLS tenant context
            uid = get_current_user_id()
            if uid:
                await session.execute(
                    text("SET LOCAL app.current_user_id = :uid"),
                    {"uid": uid},
                )

            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ── Startup connection test ─────────────────────────────────────
async def verify_db_connection() -> bool:
    """Test database connectivity on startup. Returns True if connected."""
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        # Log only the host portion (never log credentials)
        safe_url = settings.DATABASE_URL.split("@")[-1] if "@" in settings.DATABASE_URL else "***"
        logger.info("db_connected", host=safe_url)
        return True
    except Exception as e:
        logger.error("db_connection_failed", error=str(e))
        return False
