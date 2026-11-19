"""
SecureAI Code Analyzer — Main Application
"""

import asyncio
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import setup_logging, get_logger
from app.api.auth import router as auth_router
from app.api.scans import router as scans_router
from app.api.repos import router as repos_router
from app.api.webhooks import router as webhooks_router
from app.api.cicd import router as cicd_router
from app.api.metrics import router as metrics_router
from app.api.usage import router as usage_router
from app.api.compliance import router as compliance_router
from app.api.file_viewer import router as file_viewer_router
from app.db.session import get_db, verify_db_connection, async_session_factory
from app.db.schema_validator import validate_schema
from app.middleware.request_size_limit import RequestSizeLimitMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.saturation_guard import SaturationGuardMiddleware
from app.middleware.schema_error import SchemaErrorMiddleware
from app.middleware.abuse_detector import AbuseDetector

settings = get_settings()
setup_logging(debug=settings.DEBUG)
logger = get_logger("main")

# Rate limiter
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT])


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Verify database connection on startup
    connected = await verify_db_connection()
    if connected:
        logger.info("app_starting", version=settings.APP_VERSION, db="connected")
    else:
        logger.warning("app_starting", version=settings.APP_VERSION, db="NOT connected — check DATABASE_URL")

    # ── Startup schema validation ─────────────────────────────
    schema_report = None
    if connected:
        try:
            async with async_session_factory() as db:
                schema_report = await validate_schema(db)
                app.state.schema_report = schema_report
                if schema_report.is_valid:
                    logger.info(
                        "startup_schema_valid",
                        checks_passed=schema_report.checks_passed,
                    )
                else:
                    # CRITICAL — readiness probe will return 503
                    logger.critical(
                        "startup_schema_INVALID",
                        checks_passed=schema_report.checks_passed,
                        checks_failed=schema_report.checks_failed,
                        missing_columns=schema_report.missing_columns or None,
                        missing_enums=schema_report.missing_enums or None,
                        missing_indexes=schema_report.missing_indexes or None,
                        alembic_pending=schema_report.alembic_pending,
                        action="Readiness probe returns 503. Kubernetes will NOT route traffic to this instance.",
                    )
        except Exception as e:
            logger.critical("startup_schema_validation_crashed", error=str(e))
            # Create a failed report so readiness probe returns 503
            from app.db.schema_validator import SchemaReport
            schema_report = SchemaReport(is_valid=False)
            schema_report.errors.append(f"Validation crashed: {str(e)}")
            app.state.schema_report = schema_report

    # Production configuration safety checks
    if not settings.DEBUG:
        if "*" in settings.CORS_ORIGINS:
            logger.error(
                "cors_wildcard_in_production",
                message="allow_origins contains '*' — this is unsafe in production. "
                        "Set CORS_ORIGINS to explicit origins.",
            )

    # Pre-warm engine rule cache
    try:
        from engine.rule_loader import get_rule_index
        idx = get_rule_index()
        logger.info("engine_rules_loaded", total=len(idx.all_rules), languages=len(idx.languages))
    except Exception as e:
        logger.error("engine_rule_load_failed", error=str(e))

    # ── Orchestration startup ────────────────────────────────
    # Ensure SCAN_TEMP_DIR exists
    scan_temp_dir = settings.SCAN_TEMP_DIR
    if scan_temp_dir:
        os.makedirs(scan_temp_dir, exist_ok=True)
        logger.info("scan_temp_dir_ready", path=scan_temp_dir)

    # Initialize queue backend
    queue_backend = None
    try:
        from app.queue.factory import create_queue_backend
        queue_backend = create_queue_backend(settings)
    except Exception as e:
        logger.error("queue_backend_init_failed", error=str(e))

    # Start ScanSessionManager
    from app.orchestration.session_manager import ScanSessionManager
    session_manager = ScanSessionManager(
        max_per_user=settings.MAX_CONCURRENT_SCANS_PER_USER,
        max_global=settings.MAX_GLOBAL_CONCURRENT_SCANS,
        queue_backend=queue_backend,
    )
    await session_manager.start(db_factory=async_session_factory)
    app.state.session_manager = session_manager
    logger.info("session_manager_started")

    # Start periodic cleanup task
    cleanup_task = None
    try:
        from app.orchestration.cleanup_service import CleanupService
        cleanup_svc = CleanupService(temp_dir=scan_temp_dir)

        # Recover stuck scans from previous crash/restart
        try:
            async with async_session_factory() as db:
                count = await cleanup_svc.recover_stuck_scans_on_startup(db)
                if count:
                    logger.warning("startup_recovery", recovered=count)
        except Exception as e:
            logger.error("startup_recovery_failed", error=str(e))

        async def _periodic_cleanup():
            interval = settings.CLEANUP_INTERVAL_HOURS * 3600
            while True:
                try:
                    await asyncio.sleep(interval)
                    async with async_session_factory() as db:
                        await cleanup_svc.run_periodic_cleanup(db)
                    logger.info("periodic_cleanup_completed")
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error("periodic_cleanup_failed", error=str(e))

        cleanup_task = asyncio.create_task(_periodic_cleanup())
        logger.info("periodic_cleanup_scheduled", interval_hours=settings.CLEANUP_INTERVAL_HOURS)
    except Exception as e:
        logger.error("cleanup_init_failed", error=str(e))

    # ── Metrics gauge updater ─────────────────────────────────
    metrics_task = None
    try:
        import psutil
        from app.services.metrics import get_metrics

        metrics = get_metrics()

        async def _periodic_metrics():
            while True:
                try:
                    await asyncio.sleep(15)
                    # Memory usage
                    mem = psutil.virtual_memory()
                    metrics.memory_usage_percent.set(mem.percent)
                    # Active / queued scans from session manager
                    sm = app.state.session_manager
                    metrics.active_scans.set(getattr(sm, "_active_count", 0))
                    metrics.queued_scans.set(
                        sm._queue.qsize() if hasattr(sm, "_queue") else 0
                    )
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error("metrics_gauge_update_failed", error=str(e))

        metrics_task = asyncio.create_task(_periodic_metrics())
        logger.info("metrics_gauge_updater_started", interval_seconds=15)
    except ImportError:
        logger.warning("psutil_not_installed", message="Metrics gauge updater disabled — install psutil")
    except Exception as e:
        logger.error("metrics_gauge_init_failed", error=str(e))

    # Mark app as ready
    app.state.ready = True

    # Initialize KMS backend
    try:
        from app.core.kms import create_kms_backend
        kms_backend = create_kms_backend(settings)
        app.state.kms_backend = kms_backend
        logger.info("kms_backend_initialized", backend=settings.KMS_BACKEND)
    except Exception as e:
        logger.error("kms_backend_init_failed", error=str(e))

    yield

    # ── Graceful shutdown ─────────────────────────────────────
    # 1. Mark not ready (readiness probe will return 503)
    app.state.ready = False
    logger.info("graceful_shutdown_starting")

    # 2. Wait for in-flight scans to complete (up to timeout)
    shutdown_timeout = settings.GRACEFUL_SHUTDOWN_TIMEOUT
    try:
        active = getattr(session_manager, "_active_count", 0)
        if active > 0:
            logger.info("waiting_for_inflight_scans", active=active, timeout=shutdown_timeout)
            waited = 0
            while waited < shutdown_timeout:
                active = getattr(session_manager, "_active_count", 0)
                if active == 0:
                    break
                await asyncio.sleep(1)
                waited += 1
            remaining = getattr(session_manager, "_active_count", 0)
            if remaining > 0:
                logger.warning("shutdown_timeout_reached", remaining_scans=remaining)
    except Exception as e:
        logger.error("graceful_shutdown_wait_failed", error=str(e))

    # 3. Cancel metrics gauge updater
    if metrics_task and not metrics_task.done():
        metrics_task.cancel()
        try:
            await metrics_task
        except asyncio.CancelledError:
            pass
        logger.info("metrics_gauge_updater_stopped")

    # Cancel cleanup task
    if cleanup_task and not cleanup_task.done():
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        logger.info("periodic_cleanup_stopped")

    # Shutdown session manager
    await session_manager.shutdown()
    logger.info("session_manager_stopped")

    logger.info("app_shutting_down")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI-Powered Full-Stack Code Security Analyzer API",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    lifespan=lifespan,
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Abuse detector (in-memory)
app.state.abuse_detector = AbuseDetector()

# ── Middleware stack (applied in reverse order) ──────────────
# 1. Request size limit (outermost — reject before reading body)
app.add_middleware(
    RequestSizeLimitMiddleware,
    max_body_bytes=getattr(settings, "MAX_REQUEST_BODY_MB", 100) * 1024 * 1024,
)

# 2. Saturation guard (reject when overloaded, before heavy processing)
app.add_middleware(SaturationGuardMiddleware)

# 3. Security headers (CSP, HSTS, X-Frame, etc.)
app.add_middleware(SecurityHeadersMiddleware)

# 4. CORS (explicit allowed headers, not wildcard)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-Requested-With"],
)

# 5. Schema error protection (catches UndefinedColumnError → 503)
app.add_middleware(SchemaErrorMiddleware)

# Include routers (order: auth → scans → repos → cicd → webhooks)
# Auth router at root level — required for OAuth callback URLs (e.g. /auth/google/callback)
app.include_router(auth_router)
# Also mount under API prefix for frontend API calls (e.g. /api/v1/auth/me)
app.include_router(auth_router, prefix=settings.API_PREFIX)
app.include_router(scans_router, prefix=settings.API_PREFIX)
app.include_router(repos_router, prefix=settings.API_PREFIX)
# CI/CD management under API prefix (auth-protected via get_current_user)
app.include_router(cicd_router, prefix=settings.API_PREFIX)
# Usage endpoints under API prefix (auth-protected)
app.include_router(usage_router, prefix=settings.API_PREFIX)
# Compliance endpoints under API prefix (RBAC-protected)
app.include_router(compliance_router, prefix=settings.API_PREFIX)
# File viewer — serves source code for vulnerability context viewing
app.include_router(file_viewer_router, prefix=settings.API_PREFIX)
# Webhooks at root level — last to minimize middleware conflicts.
# Excluded from OpenAPI schema (public endpoint secured by HMAC, not user auth).
app.include_router(webhooks_router, include_in_schema=False)
# Metrics at root level — Prometheus scrape target (no auth, excluded from OpenAPI).
app.include_router(metrics_router)


@app.get("/")
async def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "operational",
        "docs": "/docs" if settings.DEBUG else None,
    }


@app.get("/health")
async def health():
    """Liveness probe -- always returns 200 if process is alive."""
    return {"status": "healthy"}


@app.get("/health/ready")
async def health_ready(request: Request):
    """Readiness probe -- checks critical dependencies.

    Used by load balancers and Kubernetes readiness probes.
    Returns 200 if all checks pass, 503 if any fail.
    """
    from fastapi.responses import JSONResponse
    import time

    checks = {}

    # 1. App marked ready (set after lifespan startup completes)
    checks["app_ready"] = getattr(request.app.state, "ready", False)

    # 1b. Schema validation passed (CRITICAL for Kubernetes traffic gating)
    schema_report = getattr(request.app.state, "schema_report", None)
    checks["schema_valid"] = schema_report.is_valid if schema_report else False
    if schema_report:
        checks["schema_checks_passed"] = schema_report.checks_passed
        checks["schema_checks_failed"] = schema_report.checks_failed
        if not schema_report.is_valid:
            checks["schema_errors"] = {
                "missing_columns": schema_report.missing_columns or None,
                "missing_enums": schema_report.missing_enums or None,
                "missing_indexes": schema_report.missing_indexes or None,
                "alembic_pending": schema_report.alembic_pending,
                "errors": schema_report.errors or None,
            }

    # 2. Session manager started
    sm = getattr(request.app.state, "session_manager", None)
    checks["session_manager"] = sm is not None

    # 3. Engine rules loaded
    try:
        from engine.rule_loader import get_rule_index
        idx = get_rule_index()
        checks["engine_rules"] = len(idx.all_rules) > 0
    except Exception:
        checks["engine_rules"] = False

    # 4. Memory below 95%
    try:
        import psutil
        mem = psutil.virtual_memory()
        checks["memory_ok"] = mem.percent < 95.0
    except Exception:
        checks["memory_ok"] = True  # skip if psutil unavailable

    # 5. Temp dir writable
    try:
        temp_dir = settings.SCAN_TEMP_DIR
        if temp_dir:
            test_file = os.path.join(temp_dir, ".health_check")
            with open(test_file, "w") as f:
                f.write("ok")
            os.remove(test_file)
            checks["disk_writable"] = True
        else:
            checks["disk_writable"] = True
    except Exception:
        checks["disk_writable"] = False

    all_ok = all(checks.values())
    status_code = 200 if all_ok else 503

    return JSONResponse(
        status_code=status_code,
        content={"status": "ready" if all_ok else "not_ready", "checks": checks},
    )


@app.get("/health/db")
async def health_db(db: AsyncSession = Depends(get_db)):
    """Database health check -- executes SELECT 1 against Supabase PostgreSQL."""
    try:
        await db.execute(text("SELECT 1"))
        return {"database": "connected"}
    except Exception as e:
        logger.error("health_db_failed", error=str(e))
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=500,
            content={"database": "disconnected", "error": "Database connection failed"},
        )


@app.get("/health/deep")
async def health_deep(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Deep health -- full dependency check with timing.

    Slower than /health/ready. Intended for monitoring dashboards, not
    high-frequency load balancer probes.
    """
    from fastapi.responses import JSONResponse
    import time

    checks = {}
    timings = {}

    # 1. Database SELECT 1
    t0 = time.monotonic()
    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception:
        checks["database"] = False
    timings["database_ms"] = round((time.monotonic() - t0) * 1000, 1)

    # 2. Session manager
    sm = getattr(request.app.state, "session_manager", None)
    checks["session_manager"] = sm is not None

    # 3. Engine rules
    t0 = time.monotonic()
    try:
        from engine.rule_loader import get_rule_index
        idx = get_rule_index()
        checks["engine_rules"] = len(idx.all_rules) > 0
    except Exception:
        checks["engine_rules"] = False
    timings["engine_rules_ms"] = round((time.monotonic() - t0) * 1000, 1)

    # 4. Memory
    try:
        import psutil
        mem = psutil.virtual_memory()
        checks["memory_ok"] = mem.percent < 95.0
        timings["memory_percent"] = mem.percent
    except Exception:
        checks["memory_ok"] = True

    # 5. Disk writable
    t0 = time.monotonic()
    try:
        temp_dir = settings.SCAN_TEMP_DIR
        if temp_dir:
            test_file = os.path.join(temp_dir, ".deep_health_check")
            with open(test_file, "w") as f:
                f.write("ok")
            os.remove(test_file)
            checks["disk_writable"] = True
        else:
            checks["disk_writable"] = True
    except Exception:
        checks["disk_writable"] = False
    timings["disk_ms"] = round((time.monotonic() - t0) * 1000, 1)

    # 6. Encryption key valid
    t0 = time.monotonic()
    try:
        from cryptography.fernet import Fernet
        key = settings.ENCRYPTION_KEY
        if len(key) >= 16:
            checks["encryption"] = True
        else:
            checks["encryption"] = False
    except Exception:
        checks["encryption"] = False
    timings["encryption_ms"] = round((time.monotonic() - t0) * 1000, 1)

    all_ok = all(checks.values())
    status_code = 200 if all_ok else 503

    return JSONResponse(
        status_code=status_code,
        content={
            "status": "healthy" if all_ok else "degraded",
            "checks": checks,
            "timings": timings,
        },
    )
