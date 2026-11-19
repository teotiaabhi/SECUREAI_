"""Add role, status, tier, is_paid, and resource tracking columns to users table.

Safe ALTER TABLE migration — no data loss, no table recreation.
Adds columns as NULLABLE first, backfills defaults, then sets NOT NULL.

Revision ID: 001_user_columns
Revises: None
Create Date: 2026-03-03
"""

from alembic import op
import sqlalchemy as sa

revision = "001_user_columns"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Step 1: Create enum types (IF NOT EXISTS for safety) ──────
    #
    # PostgreSQL enums must exist before columns reference them.
    # Using raw SQL because Alembic's sa.Enum doesn't support IF NOT EXISTS.

    op.execute("""
        DO $$ BEGIN
            CREATE TYPE user_role AS ENUM ('user', 'admin', 'auditor', 'developer');
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
    """)

    op.execute("""
        DO $$ BEGIN
            CREATE TYPE user_status AS ENUM ('active', 'suspended', 'deleted');
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
    """)

    op.execute("""
        DO $$ BEGIN
            CREATE TYPE user_tier AS ENUM ('free', 'pro', 'enterprise');
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
    """)

    # ── Step 2: Add columns as NULLABLE (safe for existing rows) ─
    #
    # We add WITHOUT NOT NULL first, then backfill, then add constraint.
    # This avoids "column X contains null values" errors on existing rows.

    # role — enum, default 'developer' per requirement
    op.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS role user_role DEFAULT 'developer';
    """)

    # status — enum, default 'active'
    op.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS status user_status DEFAULT 'active';
    """)

    # tier — enum, default 'free'
    op.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS tier user_tier DEFAULT 'free';
    """)

    # is_paid — boolean, default false
    op.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS is_paid BOOLEAN DEFAULT false;
    """)

    # ai_tokens_used — integer counter, default 0
    op.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS ai_tokens_used INTEGER DEFAULT 0;
    """)

    # scans_today — integer counter, default 0
    op.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS scans_today INTEGER DEFAULT 0;
    """)

    # last_scan_reset — date, nullable (no backfill needed)
    op.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS last_scan_reset DATE;
    """)

    # storage_used_bytes — bigint counter, default 0
    op.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS storage_used_bytes BIGINT DEFAULT 0;
    """)

    # ── Step 3: Backfill existing rows that have NULLs ───────────
    #
    # The DEFAULT clause on ADD COLUMN sets the value for NEW rows
    # but existing rows may have NULL if the column was added without
    # DEFAULT in some PostgreSQL versions. This UPDATE is idempotent.

    op.execute("""
        UPDATE users SET
            role = 'developer'        WHERE role IS NULL;
    """)
    op.execute("""
        UPDATE users SET
            status = 'active'         WHERE status IS NULL;
    """)
    op.execute("""
        UPDATE users SET
            tier = 'free'             WHERE tier IS NULL;
    """)
    op.execute("""
        UPDATE users SET
            is_paid = false           WHERE is_paid IS NULL;
    """)
    op.execute("""
        UPDATE users SET
            ai_tokens_used = 0        WHERE ai_tokens_used IS NULL;
    """)
    op.execute("""
        UPDATE users SET
            scans_today = 0           WHERE scans_today IS NULL;
    """)
    op.execute("""
        UPDATE users SET
            storage_used_bytes = 0    WHERE storage_used_bytes IS NULL;
    """)

    # ── Step 4: Set NOT NULL constraints (safe now — no NULLs) ───
    #
    # last_scan_reset stays NULLABLE (it's legitimately NULL until
    # the user's first scan).

    op.execute("ALTER TABLE users ALTER COLUMN role SET NOT NULL;")
    op.execute("ALTER TABLE users ALTER COLUMN status SET NOT NULL;")
    op.execute("ALTER TABLE users ALTER COLUMN tier SET NOT NULL;")
    op.execute("ALTER TABLE users ALTER COLUMN is_paid SET NOT NULL;")
    op.execute("ALTER TABLE users ALTER COLUMN ai_tokens_used SET NOT NULL;")
    op.execute("ALTER TABLE users ALTER COLUMN scans_today SET NOT NULL;")
    op.execute("ALTER TABLE users ALTER COLUMN storage_used_bytes SET NOT NULL;")

    # ── Step 5: Set server defaults (for future INSERTs) ─────────

    op.execute("ALTER TABLE users ALTER COLUMN role SET DEFAULT 'developer';")
    op.execute("ALTER TABLE users ALTER COLUMN status SET DEFAULT 'active';")
    op.execute("ALTER TABLE users ALTER COLUMN tier SET DEFAULT 'free';")
    op.execute("ALTER TABLE users ALTER COLUMN is_paid SET DEFAULT false;")
    op.execute("ALTER TABLE users ALTER COLUMN ai_tokens_used SET DEFAULT 0;")
    op.execute("ALTER TABLE users ALTER COLUMN scans_today SET DEFAULT 0;")
    op.execute("ALTER TABLE users ALTER COLUMN storage_used_bytes SET DEFAULT 0;")


def downgrade() -> None:
    # ── Reverse: drop columns (preserves table, drops data in these cols only)

    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS storage_used_bytes;")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS last_scan_reset;")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS scans_today;")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS ai_tokens_used;")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS is_paid;")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS tier;")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS status;")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS role;")

    # Drop enum types (only if no other table uses them)
    op.execute("DROP TYPE IF EXISTS user_tier;")
    op.execute("DROP TYPE IF EXISTS user_status;")
    op.execute("DROP TYPE IF EXISTS user_role;")
