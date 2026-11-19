"""
Request body size limit middleware.

Rejects requests whose Content-Length exceeds the configured maximum
before the body is read into memory. Returns 413 Payload Too Large.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests larger than max_body_bytes."""

    def __init__(self, app, max_body_bytes: int = 100 * 1024 * 1024) -> None:
        super().__init__(app)
        self.max_body_bytes = max_body_bytes

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length header"},
                )
            if length > self.max_body_bytes:
                max_mb = self.max_body_bytes // (1024 * 1024)
                return JSONResponse(
                    status_code=413,
                    content={
                        "detail": f"Request body too large. Maximum is {max_mb}MB."
                    },
                )
        return await call_next(request)
