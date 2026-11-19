"""
Security headers middleware.

Adds standard security headers to every response:
- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- X-XSS-Protection
- Strict-Transport-Security
- Referrer-Policy
- Permissions-Policy

Also logs mutation requests (POST/PUT/PATCH/DELETE) with timing.
"""

import time
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("middleware.security_headers")

DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject security headers and log mutation requests."""

    def __init__(self, app, csp_policy: str = DEFAULT_CSP) -> None:
        super().__init__(app)
        self.csp_policy = csp_policy

    async def dispatch(self, request: Request, call_next) -> Response:
        start = time.time()
        response: Response = await call_next(request)

        # Security headers
        response.headers["Content-Security-Policy"] = self.csp_policy
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )

        # Request timing
        duration = round(time.time() - start, 4)
        response.headers["X-Response-Time"] = f"{duration}s"

        # Audit log for mutations
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            logger.info(
                "api_request method=%s path=%s status=%d duration=%.4f",
                request.method,
                request.url.path,
                response.status_code,
                duration,
            )

        return response
