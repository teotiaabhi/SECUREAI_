-- ============================================================================
-- SAFE MIGRATION: Add security & tracking columns to users table
-- ============================================================================
-- Target:      Supabase PostgreSQL (paste into SQL Editor)
-- Date:        2026-03-03
-- Safety:      No data loss, no table recreation, ALTER TABLE only
-- Idempotent:  Safe to run multiple times (IF NOT EXISTS / IF EXISTS guards)
-- ============================================================================

-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │ STEP 1: Create enum types                                              │
-- └─────────────────────────────────────────────────────────────────────────┘

DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('user', 'admin', 'auditor', 'developer');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE user_status AS ENUM ('active', 'suspended', 'deleted');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE user_tier AS ENUM ('free', 'pro', 'enterprise');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;


-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │ STEP 2: Add columns (NULLABLE with DEFAULT — safe for existing rows)   │
-- └─────────────────────────────────────────────────────────────────────────┘

ALTER TABLE users ADD COLUMN IF NOT EXISTS role            user_role   DEFAULT 'developer';
ALTER TABLE users ADD COLUMN IF NOT EXISTS status          user_status DEFAULT 'active';
ALTER TABLE users ADD COLUMN IF NOT EXISTS tier            user_tier   DEFAULT 'free';
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_paid         BOOLEAN     DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS ai_tokens_used  INTEGER     DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS scans_today     INTEGER     DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_scan_reset DATE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS storage_used_bytes BIGINT   DEFAULT 0;


-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │ STEP 3: Backfill existing rows (idempotent — only touches NULLs)       │
-- └─────────────────────────────────────────────────────────────────────────┘

UPDATE users SET role              = 'developer' WHERE role IS NULL;
UPDATE users SET status            = 'active'    WHERE status IS NULL;
UPDATE users SET tier              = 'free'      WHERE tier IS NULL;
UPDATE users SET is_paid           = false       WHERE is_paid IS NULL;
UPDATE users SET ai_tokens_used    = 0           WHERE ai_tokens_used IS NULL;
UPDATE users SET scans_today       = 0           WHERE scans_today IS NULL;
UPDATE users SET storage_used_bytes = 0          WHERE storage_used_bytes IS NULL;
-- last_scan_reset stays NULL (legitimately NULL until first scan)


-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │ STEP 4: Add NOT NULL constraints (safe — no NULLs remain)              │
-- └─────────────────────────────────────────────────────────────────────────┘

ALTER TABLE users ALTER COLUMN role              SET NOT NULL;
ALTER TABLE users ALTER COLUMN status            SET NOT NULL;
ALTER TABLE users ALTER COLUMN tier              SET NOT NULL;
ALTER TABLE users ALTER COLUMN is_paid           SET NOT NULL;
ALTER TABLE users ALTER COLUMN ai_tokens_used    SET NOT NULL;
ALTER TABLE users ALTER COLUMN scans_today       SET NOT NULL;
ALTER TABLE users ALTER COLUMN storage_used_bytes SET NOT NULL;
-- last_scan_reset remains NULLABLE


-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │ STEP 5: Ensure server defaults are set (for future INSERTs)            │
-- └─────────────────────────────────────────────────────────────────────────┘

ALTER TABLE users ALTER COLUMN role              SET DEFAULT 'developer';
ALTER TABLE users ALTER COLUMN status            SET DEFAULT 'active';
ALTER TABLE users ALTER COLUMN tier              SET DEFAULT 'free';
ALTER TABLE users ALTER COLUMN is_paid           SET DEFAULT false;
ALTER TABLE users ALTER COLUMN ai_tokens_used    SET DEFAULT 0;
ALTER TABLE users ALTER COLUMN scans_today       SET DEFAULT 0;
ALTER TABLE users ALTER COLUMN storage_used_bytes SET DEFAULT 0;


-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │ VERIFY: Check the migration worked                                     │
-- └─────────────────────────────────────────────────────────────────────────┘

-- Run this SELECT to verify all columns exist with correct defaults:
-- SELECT column_name, data_type, column_default, is_nullable
-- FROM information_schema.columns
-- WHERE table_name = 'users'
--   AND column_name IN ('role', 'status', 'tier', 'is_paid',
--                        'ai_tokens_used', 'scans_today',
--                        'last_scan_reset', 'storage_used_bytes')
-- ORDER BY ordinal_position;
