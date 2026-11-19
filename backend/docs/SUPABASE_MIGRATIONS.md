# Supabase Migration Best Practices

## Database URLs

Supabase exposes **two** PostgreSQL endpoints. You MUST use the correct one:

| Endpoint | URL format | Use for |
|----------|-----------|---------|
| **Direct** (Session mode) | `postgresql://postgres.[ref]:[pw]@aws-0-[region].pooler.supabase.com:5432/postgres` | ✅ Migrations, schema changes, DDL |
| **Pooler** (Transaction mode) | `postgresql://postgres.[ref]:[pw]@aws-0-[region].pooler.supabase.com:6543/postgres` | ✅ Application runtime queries |

> **CRITICAL**: Never run Alembic migrations through the Transaction-mode pooler (port 6543).
> Transaction-mode pgBouncer does not support:
> - Multi-statement transactions required by DDL
> - `SET` commands (used by Alembic internally)
> - Advisory locks (used for migration locking)

## Environment Variables

```bash
# .env — Application runtime (uses transaction-mode pooler)
DATABASE_URL=postgresql+asyncpg://postgres.xxxx:pw@aws-0-us-east-1.pooler.supabase.com:6543/postgres

# CI/CD / Migration job (uses direct connection or session-mode pooler)
MIGRATION_DATABASE_URL=postgresql+asyncpg://postgres.xxxx:pw@aws-0-us-east-1.pooler.supabase.com:5432/postgres
```

## Connection Settings

### Runtime (via pooler — port 6543)
```python
# session.py — already configured
connect_args = {
    "ssl": ssl_context,
    "statement_cache_size": 0,         # pgBouncer: no prepared statements
    "prepared_statement_cache_size": 0, # pgBouncer: no prepared statement cache
}
```

### Migrations (direct — port 5432)
```python
# alembic/env.py — uses direct connection
# No pgBouncer restrictions, prepared statements OK
# SSL is still required
```

## Migration Workflow for Supabase

```
1. Developer creates migration locally
   └─ alembic revision --autogenerate -m "description"

2. Test migration against staging Supabase instance
   └─ MIGRATION_DATABASE_URL=... python scripts/migrate.py upgrade

3. CI/CD pipeline runs migration against production
   └─ Uses MIGRATION_DATABASE_URL (direct, port 5432)
   └─ NOT DATABASE_URL (pooler, port 6543)

4. Application starts with DATABASE_URL (pooler)
   └─ Schema validator verifies columns/enums/indexes
   └─ Readiness probe gates traffic
```

## Supabase SQL Editor Notes

- The SQL Editor connects directly to PostgreSQL (not via pooler)
- It's safe to run DDL/migrations from the SQL Editor
- Use the raw SQL files in `backend/migrations/` for manual application
- Always run the verification query after migration

## RLS (Row Level Security) Considerations

- Alembic migrations run as the `postgres` superuser — RLS is bypassed
- Application queries run through pooler where RLS policies apply
- If you add RLS policies, test migration behavior separately from app behavior
- The app sets `SET LOCAL app.current_user_id` per transaction for RLS context

## Backup Before Migration

Supabase provides point-in-time recovery (PITR) on Pro plan:
1. Note the current timestamp before running migrations
2. If migration fails, use Dashboard → Database → Backups → PITR to restore
3. Free plan: use `pg_dump` before migration

```bash
# Manual backup before migration (free plan)
pg_dump $MIGRATION_DATABASE_URL --no-owner --clean > backup_$(date +%Y%m%d_%H%M%S).sql
```
