"""
Startup Schema Validator — enterprise-grade database schema verification.

Called during app lifespan to detect migration drift BEFORE serving traffic.
Validates:
  1. Required columns exist in each table
  2. PostgreSQL enum types exist with expected values
  3. Critical indexes exist
  4. Alembic migration version matches code HEAD

Does NOT crash the app — logs CRITICAL errors and populates a SchemaReport
that the readiness probe uses to block traffic via 503.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger

logger = get_logger("schema_validator")


# ═══════════════════════════════════════════════════════════════════
# Schema Report
# ═══════════════════════════════════════════════════════════════════

@dataclass
class SchemaReport:
    """Result of startup schema validation."""
    is_valid: bool = True
    missing_columns: Dict[str, List[str]] = field(default_factory=dict)
    extra_columns: Dict[str, List[str]] = field(default_factory=dict)
    missing_enums: Dict[str, List[str]] = field(default_factory=dict)
    missing_enum_values: Dict[str, Tuple[Set[str], Set[str]]] = field(default_factory=dict)
    missing_indexes: List[str] = field(default_factory=list)
    alembic_head: Optional[str] = None
    alembic_current: Optional[str] = None
    alembic_pending: int = 0
    errors: List[str] = field(default_factory=list)
    checks_passed: int = 0
    checks_failed: int = 0

    def fail(self, error: str):
        """Record a validation failure."""
        self.is_valid = False
        self.checks_failed += 1
        self.errors.append(error)

    def ok(self):
        """Record a passed check."""
        self.checks_passed += 1


# ═══════════════════════════════════════════════════════════════════
# Expected Schema — the ground truth that the DB must satisfy
# ═══════════════════════════════════════════════════════════════════

# Table → required columns
EXPECTED_COLUMNS: Dict[str, Set[str]] = {
    "users": {
        "id", "email", "name", "provider", "avatar_url",
        "google_id", "github_token_encrypted",
        "role", "status", "tier", "is_paid",
        "ai_tokens_used", "scans_today", "last_scan_reset",
        "storage_used_bytes", "created_at",
    },
}

# Enum type → expected values
EXPECTED_ENUMS: Dict[str, Set[str]] = {
    "user_role": {"user", "admin", "auditor", "developer"},
    "user_status": {"active", "suspended", "deleted"},
    "user_tier": {"free", "pro", "enterprise"},
}

# Critical indexes that must exist for query performance and constraints.
# Format: (table_name, column_name) — checks pg_indexes for any index
# that covers this column (including unique constraints and PKs).
EXPECTED_INDEXES: List[Tuple[str, str]] = [
    ("users", "email"),       # Unique constraint + lookup
    ("users", "google_id"),   # OAuth lookup
]


# ═══════════════════════════════════════════════════════════════════
# Validation Functions
# ═══════════════════════════════════════════════════════════════════

async def _check_columns(session: AsyncSession, report: SchemaReport) -> None:
    """Validate that all expected columns exist in each table."""
    for table_name, expected_cols in EXPECTED_COLUMNS.items():
        try:
            result = await session.execute(
                text("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_schema = 'public'
                      AND table_name = :table_name
                """),
                {"table_name": table_name},
            )
            db_columns = {row[0] for row in result.fetchall()}

            if not db_columns:
                report.fail(f"Table '{table_name}' not found in database")
                logger.critical(
                    "schema_table_missing",
                    table=table_name,
                    impact="All queries to this table will fail",
                )
                continue

            missing = expected_cols - db_columns
            extra = db_columns - expected_cols

            if missing:
                report.is_valid = False
                report.checks_failed += 1
                report.missing_columns[table_name] = sorted(missing)
                logger.critical(
                    "schema_columns_missing",
                    table=table_name,
                    missing=sorted(missing),
                    count=len(missing),
                    impact="Queries referencing these columns will crash at runtime",
                )
            else:
                report.ok()

            if extra:
                report.extra_columns[table_name] = sorted(extra)
                logger.info(
                    "schema_extra_columns",
                    table=table_name,
                    extra=sorted(extra),
                )

        except Exception as e:
            report.fail(f"Failed to inspect table '{table_name}': {str(e)}")
            logger.critical("schema_inspect_failed", table=table_name, error=str(e))


async def _check_enums(session: AsyncSession, report: SchemaReport) -> None:
    """Validate that expected PostgreSQL enum types exist with correct values."""
    for enum_name, expected_values in EXPECTED_ENUMS.items():
        try:
            # Query pg_enum for the enum type's labels
            result = await session.execute(
                text("""
                    SELECT e.enumlabel
                    FROM pg_type t
                    JOIN pg_enum e ON t.oid = e.enumtypid
                    WHERE t.typname = :enum_name
                    ORDER BY e.enumsortorder
                """),
                {"enum_name": enum_name},
            )
            db_values = {row[0] for row in result.fetchall()}

            if not db_values:
                # Enum type doesn't exist at all
                report.is_valid = False
                report.checks_failed += 1
                report.missing_enums[enum_name] = sorted(expected_values)
                logger.critical(
                    "schema_enum_missing",
                    enum=enum_name,
                    expected_values=sorted(expected_values),
                    impact=f"Columns using '{enum_name}' type cannot be created",
                )
                continue

            missing_vals = expected_values - db_values
            if missing_vals:
                report.is_valid = False
                report.checks_failed += 1
                report.missing_enum_values[enum_name] = (missing_vals, db_values)
                logger.critical(
                    "schema_enum_values_missing",
                    enum=enum_name,
                    missing=sorted(missing_vals),
                    existing=sorted(db_values),
                    impact="INSERT/UPDATE with these values will fail",
                )
            else:
                report.ok()
                logger.debug(
                    "schema_enum_ok",
                    enum=enum_name,
                    values=sorted(db_values),
                )

        except Exception as e:
            report.fail(f"Failed to inspect enum '{enum_name}': {str(e)}")
            logger.critical("schema_enum_inspect_failed", enum=enum_name, error=str(e))


async def _check_indexes(session: AsyncSession, report: SchemaReport) -> None:
    """Validate that critical indexes exist."""
    for table_name, column_name in EXPECTED_INDEXES:
        try:
            # Check pg_indexes for any index covering this column.
            # indexdef contains the column names in the CREATE INDEX statement.
            result = await session.execute(
                text("""
                    SELECT indexname
                    FROM pg_indexes
                    WHERE schemaname = 'public'
                      AND tablename = :table_name
                      AND indexdef ILIKE :column_pattern
                    LIMIT 1
                """),
                {
                    "table_name": table_name,
                    "column_pattern": f"%{column_name}%",
                },
            )
            row = result.fetchone()

            if row:
                report.ok()
                logger.debug(
                    "schema_index_ok",
                    table=table_name,
                    column=column_name,
                    index=row[0],
                )
            else:
                report.is_valid = False
                report.checks_failed += 1
                index_label = f"{table_name}.{column_name}"
                report.missing_indexes.append(index_label)
                logger.critical(
                    "schema_index_missing",
                    table=table_name,
                    column=column_name,
                    impact=f"Queries filtering on {index_label} will be slow (full table scan)",
                )

        except Exception as e:
            report.fail(f"Failed to check index {table_name}.{column_name}: {str(e)}")
            logger.critical(
                "schema_index_inspect_failed",
                table=table_name,
                column=column_name,
                error=str(e),
            )


async def _check_alembic_version(session: AsyncSession, report: SchemaReport) -> None:
    """Check Alembic migration version: current vs head."""

    # Current version from database
    try:
        result = await session.execute(
            text("SELECT version_num FROM alembic_version LIMIT 1")
        )
        row = result.fetchone()
        report.alembic_current = row[0] if row else None
    except Exception:
        report.alembic_current = None
        logger.warning("schema_no_alembic_version_table")

    # Head version from migration scripts
    try:
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        config = Config("alembic.ini")
        script = ScriptDirectory.from_config(config)
        heads = script.get_heads()
        report.alembic_head = heads[0] if heads else None

        if report.alembic_head and report.alembic_current:
            if report.alembic_head != report.alembic_current:
                revs = list(script.walk_revisions(
                    report.alembic_head,
                    report.alembic_current,
                ))
                report.alembic_pending = max(0, len(revs) - 1)
                report.is_valid = False
                report.checks_failed += 1
                logger.critical(
                    "schema_migrations_pending",
                    head=report.alembic_head,
                    current=report.alembic_current,
                    pending=report.alembic_pending,
                    impact="Database schema does not match application code",
                )
            else:
                report.ok()
        elif report.alembic_head and not report.alembic_current:
            report.alembic_pending = -1
            report.checks_failed += 1
            logger.critical(
                "schema_no_version_tracked",
                head=report.alembic_head,
                impact="No migrations have been applied — schema may be empty",
            )
    except Exception as e:
        logger.warning("schema_alembic_head_check_failed", error=str(e))


# ═══════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════

async def validate_schema(session: AsyncSession) -> SchemaReport:
    """
    Run all schema validation checks.

    Returns a SchemaReport. The app does NOT crash on mismatch —
    instead, the readiness probe returns 503 and Kubernetes/LB
    stops routing traffic to this instance.
    """
    report = SchemaReport()

    logger.info("schema_validation_starting")

    # Run all checks
    await _check_columns(session, report)
    await _check_enums(session, report)
    await _check_indexes(session, report)
    await _check_alembic_version(session, report)

    # ── Summary ─────────────────────────────────────────────────
    if report.is_valid:
        logger.info(
            "schema_validation_passed",
            checks_passed=report.checks_passed,
            alembic_current=report.alembic_current,
        )
    else:
        logger.critical(
            "schema_validation_FAILED",
            checks_passed=report.checks_passed,
            checks_failed=report.checks_failed,
            missing_columns=report.missing_columns or None,
            missing_enums=report.missing_enums or None,
            missing_indexes=report.missing_indexes or None,
            alembic_pending=report.alembic_pending,
            errors=report.errors or None,
            action="Readiness probe will return 503. Traffic will be blocked.",
        )

    return report
