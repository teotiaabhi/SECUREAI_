"""
Safe Large-Table Migration Pattern — Zero-Downtime Column Addition

This is a TEMPLATE for safely adding columns to large PostgreSQL tables
(millions of rows) without long locks or downtime.

The pattern splits the work into 3 separate migrations:
  Migration 1: Add nullable column (instant, no table rewrite)
  Migration 2: Backfill defaults in batches (no locks)
  Migration 3: Add NOT NULL constraint (after backfill completes)

Why 3 migrations?
  - ADD COLUMN ... DEFAULT in PostgreSQL 11+ is instant (no table rewrite)
    but only if the column is NULLABLE.
  - UPDATE in one transaction on millions of rows holds a long lock.
    Batching avoids this.
  - SET NOT NULL requires a full table scan to verify, but it's fast
    if done after all rows are populated.

Usage:
  1. Copy this template
  2. Replace TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, DEFAULT_VALUE
  3. Create 3 Alembic migration files or run as raw SQL
"""

from alembic import op
import sqlalchemy as sa


# ═══════════════════════════════════════════════════════════════════
# CONFIG — Replace these values for each migration
# ═══════════════════════════════════════════════════════════════════
TABLE_NAME = "users"
COLUMN_NAME = "role"
COLUMN_TYPE = "user_role"  # Enum type or standard PostgreSQL type
DEFAULT_VALUE = "'developer'"
BATCH_SIZE = 5000


# ═══════════════════════════════════════════════════════════════════
# MIGRATION 1 — Add nullable column (instant, no lock)
# ═══════════════════════════════════════════════════════════════════

def migration_1_add_nullable_column():
    """
    Phase 1: Add column as NULLABLE with DEFAULT.

    In PostgreSQL 11+, ADD COLUMN ... DEFAULT on a NULLABLE column
    is a metadata-only operation — it does NOT rewrite the table
    and holds only a brief ACCESS EXCLUSIVE lock (~milliseconds).

    Existing rows get the DEFAULT value lazily on read.
    """
    op.execute(f"""
        ALTER TABLE {TABLE_NAME}
        ADD COLUMN IF NOT EXISTS {COLUMN_NAME} {COLUMN_TYPE}
        DEFAULT {DEFAULT_VALUE};
    """)


# ═══════════════════════════════════════════════════════════════════
# MIGRATION 2 — Backfill in batches (no long locks)
# ═══════════════════════════════════════════════════════════════════

def migration_2_backfill_batched():
    """
    Phase 2: Backfill existing NULL rows in small batches.

    This runs UPDATE on BATCH_SIZE rows at a time to avoid holding
    a lock on the entire table. Each batch commits independently.

    For PostgreSQL 11+ with lazy-DEFAULT this is usually not needed,
    but it IS needed if:
      - You're on PostgreSQL 10 or earlier
      - The column was added WITHOUT DEFAULT
      - You need to run a complex computation per row

    This is safe to run while the app is live — each batch holds
    a ROW-level lock only for the duration of the mini-transaction.
    """
    # Raw SQL batched update — runs outside Alembic's transaction
    op.execute(f"""
        DO $$
        DECLARE
            batch_count INT := 0;
            total_updated INT := 0;
            rows_affected INT;
        BEGIN
            LOOP
                UPDATE {TABLE_NAME}
                SET {COLUMN_NAME} = {DEFAULT_VALUE}
                WHERE {COLUMN_NAME} IS NULL
                  AND ctid IN (
                      SELECT ctid FROM {TABLE_NAME}
                      WHERE {COLUMN_NAME} IS NULL
                      LIMIT {BATCH_SIZE}
                  );

                GET DIAGNOSTICS rows_affected = ROW_COUNT;
                total_updated := total_updated + rows_affected;
                batch_count := batch_count + 1;

                -- Commit each batch (releases locks)
                COMMIT;

                EXIT WHEN rows_affected = 0;

                -- Brief pause to reduce load on production DB
                PERFORM pg_sleep(0.1);
            END LOOP;

            RAISE NOTICE 'Backfill complete: % rows in % batches',
                         total_updated, batch_count;
        END $$;
    """)


# ═══════════════════════════════════════════════════════════════════
# MIGRATION 3 — Add NOT NULL constraint (after backfill)
# ═══════════════════════════════════════════════════════════════════

def migration_3_set_not_null():
    """
    Phase 3: Add NOT NULL constraint.

    Only run this AFTER Migration 2 has completed and verified
    that zero rows have NULL values in the column.

    In PostgreSQL 12+, if there's a CHECK constraint that validates
    NOT NULL, the SET NOT NULL is instant. Otherwise it does a
    full table scan (fast, but holds ACCESS EXCLUSIVE lock briefly).

    Optional optimization for very large tables:
      1. Add a CHECK constraint first (NOT VALID — instant)
      2. VALIDATE CONSTRAINT (scans table, holds SHARE UPDATE EXCLUSIVE — no writes blocked)
      3. SET NOT NULL (instant, because CHECK already validates)
    """

    # Option A: Simple SET NOT NULL (fine for < 10M rows)
    op.execute(f"""
        ALTER TABLE {TABLE_NAME}
        ALTER COLUMN {COLUMN_NAME} SET NOT NULL;
    """)

    # Option B: Lock-free for very large tables (uncomment if needed)
    # op.execute(f"""
    #     -- Step 1: Add CHECK NOT NULL constraint without validation (instant)
    #     ALTER TABLE {TABLE_NAME}
    #     ADD CONSTRAINT {TABLE_NAME}_{COLUMN_NAME}_not_null
    #     CHECK ({COLUMN_NAME} IS NOT NULL)
    #     NOT VALID;
    #
    #     -- Step 2: Validate (scans table but does NOT block writes)
    #     ALTER TABLE {TABLE_NAME}
    #     VALIDATE CONSTRAINT {TABLE_NAME}_{COLUMN_NAME}_not_null;
    #
    #     -- Step 3: Set NOT NULL (instant — PostgreSQL trusts the CHECK)
    #     ALTER TABLE {TABLE_NAME}
    #     ALTER COLUMN {COLUMN_NAME} SET NOT NULL;
    #
    #     -- Step 4: Drop the CHECK (no longer needed)
    #     ALTER TABLE {TABLE_NAME}
    #     DROP CONSTRAINT {TABLE_NAME}_{COLUMN_NAME}_not_null;
    # """)


# ═══════════════════════════════════════════════════════════════════
# Example Raw SQL (for Supabase SQL Editor)
# ═══════════════════════════════════════════════════════════════════

RAW_SQL_PATTERN = """
-- ============================================================
-- SAFE LARGE-TABLE COLUMN ADDITION — Zero Downtime Pattern
-- ============================================================
-- Table: {table}
-- Column: {column} ({type})
-- Default: {default}
-- ============================================================

-- PHASE 1: Add nullable column (instant in PG 11+)
ALTER TABLE {table}
ADD COLUMN IF NOT EXISTS {column} {type} DEFAULT {default};

-- PHASE 2: Backfill in batches (run as separate transaction)
DO $$
DECLARE
    rows_affected INT;
BEGIN
    LOOP
        UPDATE {table}
        SET {column} = {default}
        WHERE {column} IS NULL
          AND ctid IN (
              SELECT ctid FROM {table}
              WHERE {column} IS NULL
              LIMIT 5000
          );
        GET DIAGNOSTICS rows_affected = ROW_COUNT;
        EXIT WHEN rows_affected = 0;
        PERFORM pg_sleep(0.1);
    END LOOP;
END $$;

-- PHASE 3: Add NOT NULL (only after Phase 2 verifies zero NULLs)
ALTER TABLE {table}
ALTER COLUMN {column} SET NOT NULL;

-- PHASE 3b: (OPTIONAL) Lock-free NOT NULL for 100M+ row tables:
-- ALTER TABLE {table} ADD CONSTRAINT {table}_{column}_nn
--   CHECK ({column} IS NOT NULL) NOT VALID;
-- ALTER TABLE {table} VALIDATE CONSTRAINT {table}_{column}_nn;
-- ALTER TABLE {table} ALTER COLUMN {column} SET NOT NULL;
-- ALTER TABLE {table} DROP CONSTRAINT {table}_{column}_nn;
""".format(
    table=TABLE_NAME,
    column=COLUMN_NAME,
    type=COLUMN_TYPE,
    default=DEFAULT_VALUE,
)
