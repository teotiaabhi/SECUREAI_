#!/bin/sh
# =============================================================================
# Docker Entrypoint — Pre-Start Migration Runner
# =============================================================================
# Runs Alembic migrations BEFORE the app starts. If migrations fail, the
# container exits with code 1 and the orchestrator (K8s, ECS, Compose)
# handles retry/rollback.
#
# Environment:
#   DATABASE_URL        — Required. PostgreSQL connection string.
#   SKIP_MIGRATIONS     — Set to "true" to bypass migrations (debugging only).
#   MIGRATION_ENV       — dev / staging / prod (default: prod in Docker).
# =============================================================================

set -e

echo "=========================================="
echo " SecureAI Code Analyzer — Startup"
echo "=========================================="

# ── 1. Pre-flight: verify DATABASE_URL is set ───────────────────
if [ -z "$DATABASE_URL" ]; then
    echo "[FATAL] DATABASE_URL is not set. Cannot start."
    exit 1
fi

# ── 2. Run migrations (unless explicitly skipped) ───────────────
if [ "$SKIP_MIGRATIONS" = "true" ]; then
    echo "[WARN] SKIP_MIGRATIONS=true — skipping Alembic migrations."
    echo "[WARN] Only use this for debugging. Never skip in production."
else
    export MIGRATION_ENV="${MIGRATION_ENV:-prod}"
    echo "[INFO] Running database migrations (env=$MIGRATION_ENV)..."

    python scripts/migrate.py upgrade
    MIGRATE_EXIT=$?

    if [ $MIGRATE_EXIT -ne 0 ]; then
        echo "[FATAL] Migration failed (exit=$MIGRATE_EXIT). Container will NOT start."
        echo "[FATAL] Fix the migration and redeploy."
        exit 1
    fi

    echo "[INFO] Migrations applied successfully."

    # ── 3. Schema check (verify we're at head) ──────────────────
    echo "[INFO] Verifying schema is at head..."
    python scripts/migrate.py check
    CHECK_EXIT=$?

    if [ $CHECK_EXIT -ne 0 ]; then
        echo "[WARN] Schema check returned exit=$CHECK_EXIT."
        echo "[WARN] App will start but may encounter runtime errors."
    fi
fi

echo "=========================================="
echo " Starting application server"
echo "=========================================="

# ── 4. Exec into the actual command (uvicorn) ──────────────────
# Using exec replaces this shell process with uvicorn, so tini
# correctly forwards signals (SIGTERM for graceful shutdown).
exec "$@"
