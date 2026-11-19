"""
Saturation guard middleware — rejects requests with 503 when
system resources are exhausted.

Protects the server from cascading overload by checking:
1. Memory pressure (psutil)
2. Active scan count vs. global limit
3. Queue depth vs. max queue depth

Health checks, metrics, and status queries always pass through.
"""

import psutil
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger("saturation_guard")

# Paths that always pass through (liveness, metrics, status)
_PASSTHROUGH_PREFIXES = (
    "/health",
    "/metrics",
    "/docs",
    "/redoc",
    "/openapi.json",
)

# Paths where saturation is enforced (scan start, upload)
_SCAN_START_PATTERNS = (
    "/scan/start",
    "/scan/upload",
)


class SaturationGuardMiddleware(BaseHTTPMiddleware):
    """Returns 503 when the system is saturated."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Always pass through health/metrics/docs
        if any(path.startswith(p) for p in _PASSTHROUGH_PREFIXES):
            return await call_next(request)

        settings = get_settings()
        memory_threshold = getattr(settings, "SATURATION_MEMORY_THRESHOLD", 90.0)
        max_queue = getattr(settings, "SATURATION_MAX_QUEUE_DEPTH", 50)

        # Check 1: Global memory pressure — reject ALL requests
        try:
            mem = psutil.virtual_memory()
            if mem.percent > memory_threshold:
                logger.warning(
                    "saturation_memory",
                    memory_percent=mem.percent,
                    threshold=memory_threshold,
                )
                return JSONResponse(
                    status_code=503,
                    content={
                        "detail": "Server under memory pressure — try again later",
                        "retry_after": 30,
                    },
                    headers={"Retry-After": "30"},
                )
        except Exception:
            pass  # psutil failure should not block requests

        # Checks 2 & 3 only apply to scan creation endpoints
        is_scan_start = any(path.endswith(p) for p in _SCAN_START_PATTERNS)
        if is_scan_start:
            sm = getattr(request.app.state, "session_manager", None)
            if sm is not None:
                # Check 2: Active scans at global max
                active = getattr(sm, "_active_count", 0)
                max_global = getattr(settings, "MAX_GLOBAL_CONCURRENT_SCANS", 20)
                if active >= max_global:
                    logger.warning(
                        "saturation_active_scans",
                        active=active,
                        max_global=max_global,
                    )
                    return JSONResponse(
                        status_code=503,
                        content={
                            "detail": "All scan slots occupied — try again later",
                            "retry_after": 60,
                        },
                        headers={"Retry-After": "60"},
                    )

                # Check 3: Queue depth
                queue_size = sm._queue.qsize() if hasattr(sm, "_queue") else 0
                if queue_size > max_queue:
                    logger.warning(
                        "saturation_queue_depth",
                        queue_size=queue_size,
                        max_queue=max_queue,
                    )
                    return JSONResponse(
                        status_code=503,
                        content={
                            "detail": "Scan queue is full — try again later",
                            "retry_after": 120,
                        },
                        headers={"Retry-After": "120"},
                    )

        return await call_next(request)
