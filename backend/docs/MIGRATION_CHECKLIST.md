# Production Migration Safety Checklist

Use this checklist before EVERY production migration. Do not skip steps.

## Pre-Migration

- [ ] **Migration tested in staging**
  - Run against staging Supabase instance with production-like data
  - Verify no errors in Alembic output
  - Verify `migrate.py check` passes after migration

- [ ] **Rollback script ready**
  - `alembic downgrade -1` tested and verified
  - Raw SQL rollback prepared for emergency (no Alembic dependency)
  - Rollback does NOT drop data unintentionally

- [ ] **Backup taken**
  - Supabase Pro: note PITR timestamp before migration
  - Supabase Free: `pg_dump` snapshot saved
  - Backup verified (can be restored)

- [ ] **Migration duration estimated**
  - Tested against staging with representative data volume
  - Large tables: batched backfill timing measured
  - Lock duration measured (should be < 1 second per DDL statement)

- [ ] **Direct DB URL configured**
  - CI/CD uses `MIGRATION_DATABASE_URL` (port 5432, direct)
  - NOT using transaction-mode pooler (port 6543)
  - SSL enabled for Supabase connection

- [ ] **Dependencies reviewed**
  - No breaking changes for currently running application code
  - New columns are NULLABLE or have safe defaults
  - No column renames or type changes without app coordination

## During Migration

- [ ] **Monitoring dashboard open**
  - Supabase Dashboard → Database → Active queries visible
  - Application logs streaming (search for `CRITICAL`)
  - Readiness probe endpoint visible (`/health/ready`)

- [ ] **Migration executed via CI/CD**
  - `python scripts/migrate.py upgrade`
  - Watch output for errors
  - Verify exit code = 0

- [ ] **Schema check passed**
  - `python scripts/migrate.py check` returns exit 0
  - HEAD revision matches database version

## Post-Migration

- [ ] **Health probe validated**
  - `curl /health/ready` returns 200
  - `schema_valid: true` in response
  - All `schema_checks_passed` > 0, `schema_checks_failed` == 0

- [ ] **Application verified**
  - Login flow works (OAuth callback → /auth/me → 200)
  - Core features tested (scans, repos, dashboard)
  - No 503 "System upgrading" responses

- [ ] **Monitoring alert configured**
  - Alert on `schema_validation_FAILED` log event
  - Alert on `schema_error_caught_at_runtime` log event
  - Alert on `/health/ready` returning 503

- [ ] **Rollback plan documented**
  - Team knows how to rollback if issues found in next 24h
  - Rollback command documented in runbook
  - Communication plan for user-facing downtime

## Emergency Rollback

```bash
# Option 1: Alembic rollback
cd backend
MIGRATION_DATABASE_URL=... python scripts/migrate.py downgrade -1 --force

# Option 2: Supabase PITR (Pro plan)
# Dashboard → Database → Backups → Point in Time Recovery
# Restore to timestamp noted in Pre-Migration step

# Option 3: Raw SQL (last resort)
# Run the downgrade() function SQL from the migration file
# against Supabase SQL Editor
```
