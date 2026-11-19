"""
SchemaErrorMiddleware — runtime protection against schema mismatch errors.

Catches asyncpg.exceptions.UndefinedColumnError, UndefinedTableError, and
similar ProgrammingError exceptions at the middleware level. Returns a
generic 503 "System upgrading" response instead of leaking SQL errors
to the client.

Security:
  - NEVER exposes raw SQL error details to the user
  - Logs full error internally for debugging
  - Returns consistent 503 JSON body
"""

import traceback
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.logging import get_logger

logger = get_logger("schema_error_middleware")

# PostgreSQL error classes that indicate schema mismatch.
# These are string-matched against the exception message because
# asyncpg exceptions may not always be directly importable.
SCHEMA_ERROR_PATTERNS = (
    "UndefinedColumn",
    "UndefinedTable",
    "UndefinedObject",       # Missing enum type
    "InvalidColumnReference",
    "column .* does not exist",
    "relation .* does not exist",
    "type .* does not exist",
)


def _is_schema_error(exc: Exception) -> bool:
    """Check if an exception is a schema-related database error."""
    exc_type = type(exc).__name__
    exc_msg = str(exc).lower()

    # Direct asyncpg exception class match
    if exc_type in ("UndefinedColumnError", "UndefinedTableError",
                    "UndefinedObjectError", "InvalidColumnReferenceError"):
        return True

    # SQLAlchemy wraps asyncpg errors — check the cause chain
    cause = exc.__cause__ or exc
    cause_type = type(cause).__name__
    if cause_type in ("UndefinedColumnError", "UndefinedTableError",
                      "UndefinedObjectError", "InvalidColumnReferenceError"):
        return True

    # Fallback: pattern match on the message
    if "does not exist" in exc_msg and ("column" in exc_msg or
                                         "relation" in exc_msg or
                                         "type" in exc_msg):
        return True

    # Check for ProgrammingError with schema-related content
    if exc_type == "ProgrammingError" and "does not exist" in exc_msg:
        return True

    return False


class SchemaErrorMiddleware(BaseHTTPMiddleware):
    """
    Middleware that intercepts schema-mismatch database errors and returns
    a safe 503 response. Prevents SQL error details from reaching the user.

    Must be added AFTER CORSMiddleware in the middleware stack so CORS
    headers are still applied to the 503 response.
    """

    async def dispatch(self, request: Request, call_next):
        try:
            response = await call_next(request)
            return response

        except Exception as exc:
            if _is_schema_error(exc):
                # Log the full error internally — NEVER expose to user
                logger.critical(
                    "schema_error_caught_at_runtime",
                    path=request.url.path,
                    method=request.method,
                    error_type=type(exc).__name__,
                    error_detail=str(exc),
                    cause_type=type(exc.__cause__).__name__ if exc.__cause__ else None,
                    traceback=traceback.format_exc(),
                )

                # Return generic 503 — safe for users
                return JSONResponse(
                    status_code=503,
                    content={
                        "status": "unavailable",
                        "message": "System is upgrading. Please try again shortly.",
                        "code": "SCHEMA_UPGRADE_IN_PROGRESS",
                        "retry_after": 30,
                    },
                    headers={
                        "Retry-After": "30",
                        "Cache-Control": "no-store",
                    },
                )

            # Not a schema error — re-raise for other handlers
            raise
