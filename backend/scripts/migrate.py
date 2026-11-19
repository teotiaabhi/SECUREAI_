#!/usr/bin/env python3
"""
Enterprise Migration Runner — CLI for safe Alembic migrations.

Usage:
    python scripts/migrate.py upgrade              # upgrade to head
    python scripts/migrate.py upgrade --revision abc123
    python scripts/migrate.py downgrade -1         # rollback one step
    python scripts/migrate.py current              # show current revision
    python scripts/migrate.py check                # verify schema is at head (CI gate)
    python scripts/migrate.py history              # show migration history

Environment:
    MIGRATION_DATABASE_URL — Direct PostgreSQL URL for migrations (preferred)
    DATABASE_URL           — Fallback if MIGRATION_DATABASE_URL not set
    MIGRATION_ENV          — dev / staging / prod (default: dev)
    ALEMBIC_CONFIG         — path to alembic.ini (default: alembic.ini)

Exit codes:
    0 — success
    1 — migration failed
    2 — schema mismatch (check mode)
    3 — database unreachable
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# Ensure the backend directory is on sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))
os.chdir(BACKEND_DIR)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("migrate")


def _get_migration_url() -> str:
    """Get the database URL for migrations.

    Prefers MIGRATION_DATABASE_URL (direct connection, port 5432)
    over DATABASE_URL (which may be a transaction-mode pooler on port 6543).

    Supabase: Transaction-mode pgBouncer (port 6543) does NOT support
    multi-statement DDL transactions required by Alembic.
    """
    url = os.environ.get("MIGRATION_DATABASE_URL") or os.environ.get("DATABASE_URL", "")

    if not url:
        return ""

    # Warn if using pooler URL (port 6543) for migrations
    if ":6543" in url:
        logger.warning(
            "Using pooler URL (port 6543) for migrations. "
            "This may fail with Supabase transaction-mode pgBouncer. "
            "Set MIGRATION_DATABASE_URL to the direct connection (port 5432)."
        )

    return url


def get_alembic_config():
    """Build Alembic Config, overriding sqlalchemy.url from environment."""
    from alembic.config import Config

    config_path = os.environ.get("ALEMBIC_CONFIG", "alembic.ini")
    if not Path(config_path).exists():
        logger.error("Alembic config not found: %s", config_path)
        sys.exit(1)

    config = Config(config_path)

    # Override sqlalchemy.url from environment (never use hardcoded value in prod)
    db_url = _get_migration_url()
    if db_url:
        config.set_main_option("sqlalchemy.url", db_url)
    else:
        logger.warning(
            "Neither MIGRATION_DATABASE_URL nor DATABASE_URL set — "
            "falling back to alembic.ini value. This is unsafe in production."
        )

    return config


def test_connectivity():
    """Quick connectivity test using asyncpg. Returns True if DB is reachable."""
    import asyncio

    async def _test():
        db_url = _get_migration_url()
        if not db_url:
            return False

        # Parse async URL for asyncpg direct connection
        # asyncpg expects postgresql:// not postgresql+asyncpg://
        clean_url = db_url.replace("postgresql+asyncpg://", "postgresql://")

        try:
            import asyncpg
            conn = await asyncpg.connect(clean_url, timeout=10,
                                         statement_cache_size=0)
            await conn.execute("SELECT 1")
            await conn.close()
            return True
        except ImportError:
            # asyncpg not available — skip connectivity test
            logger.warning("asyncpg not installed, skipping connectivity test")
            return True
        except Exception as e:
            logger.error("Database connectivity test failed: %s", e)
            return False

    return asyncio.run(_test())


def cmd_upgrade(args):
    """Run alembic upgrade."""
    from alembic import command

    config = get_alembic_config()
    revision = args.revision or "head"

    env_name = os.environ.get("MIGRATION_ENV", "dev")
    logger.info("=== Migration UPGRADE [%s] → %s ===", env_name, revision)

    if not test_connectivity():
        logger.error("Cannot reach database. Aborting migration.")
        sys.exit(3)

    try:
        command.upgrade(config, revision)
        logger.info("=== Migration UPGRADE completed successfully ===")
    except Exception as e:
        logger.error("Migration UPGRADE failed: %s", e, exc_info=True)
        sys.exit(1)


def cmd_downgrade(args):
    """Run alembic downgrade."""
    from alembic import command

    config = get_alembic_config()
    revision = args.revision or "-1"

    env_name = os.environ.get("MIGRATION_ENV", "dev")
    logger.info("=== Migration DOWNGRADE [%s] → %s ===", env_name, revision)

    if env_name == "prod" and not args.force:
        logger.error(
            "Downgrade in production requires --force flag. Aborting."
        )
        sys.exit(1)

    try:
        command.downgrade(config, revision)
        logger.info("=== Migration DOWNGRADE completed ===")
    except Exception as e:
        logger.error("Migration DOWNGRADE failed: %s", e, exc_info=True)
        sys.exit(1)


def cmd_current(args):
    """Show current alembic revision."""
    from alembic import command

    config = get_alembic_config()
    command.current(config, verbose=True)


def cmd_history(args):
    """Show migration history."""
    from alembic import command

    config = get_alembic_config()
    command.history(config, verbose=True)


def cmd_check(args):
    """Verify that database is at the latest migration head. CI/CD gate."""
    from alembic import command
    from alembic.script import ScriptDirectory
    from alembic.runtime.migration import MigrationContext

    config = get_alembic_config()

    if not test_connectivity():
        logger.error("Cannot reach database. Schema check failed.")
        sys.exit(3)

    # Get the head revision from migration scripts
    script = ScriptDirectory.from_config(config)
    head_revisions = script.get_heads()

    if not head_revisions:
        logger.info("No migrations found — nothing to check.")
        sys.exit(0)

    # Get current revision from database
    import sqlalchemy

    db_url = _get_migration_url()
    sync_url = db_url.replace("postgresql+asyncpg://", "postgresql://")

    try:
        engine = sqlalchemy.create_engine(sync_url)
        with engine.connect() as conn:
            context = MigrationContext.configure(conn)
            current_revisions = context.get_current_heads()
        engine.dispose()
    except Exception as e:
        logger.error("Failed to read alembic_version: %s", e)
        sys.exit(3)

    head_set = set(head_revisions)
    current_set = set(current_revisions)

    if head_set == current_set:
        logger.info(
            "✅ Schema is at head: %s",
            ", ".join(head_set),
        )
        sys.exit(0)
    else:
        logger.error(
            "❌ Schema mismatch! HEAD=%s  CURRENT=%s",
            ", ".join(head_set) or "(none)",
            ", ".join(current_set) or "(none — no migrations applied)",
        )
        logger.error(
            "Run 'python scripts/migrate.py upgrade' to apply pending migrations."
        )
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(
        description="Enterprise Migration Runner for FastAPI + Supabase",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    subparsers = parser.add_subparsers(dest="command", help="Migration command")

    # upgrade
    p_up = subparsers.add_parser("upgrade", help="Apply migrations")
    p_up.add_argument("--revision", "-r", default=None, help="Target revision (default: head)")
    p_up.set_defaults(func=cmd_upgrade)

    # downgrade
    p_down = subparsers.add_parser("downgrade", help="Rollback migrations")
    p_down.add_argument("revision", nargs="?", default="-1", help="Target revision (default: -1)")
    p_down.add_argument("--force", action="store_true", help="Allow downgrade in production")
    p_down.set_defaults(func=cmd_downgrade)

    # current
    p_cur = subparsers.add_parser("current", help="Show current revision")
    p_cur.set_defaults(func=cmd_current)

    # history
    p_hist = subparsers.add_parser("history", help="Show migration history")
    p_hist.set_defaults(func=cmd_history)

    # check
    p_chk = subparsers.add_parser("check", help="Verify schema matches head (CI gate)")
    p_chk.set_defaults(func=cmd_check)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
