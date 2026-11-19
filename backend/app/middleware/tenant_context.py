"""
Tenant context — propagates authenticated user ID via contextvars.

Used by:
- jwt_handler.get_current_user: calls set_current_user_id() after auth
- db/session.get_db: calls get_current_user_id() to SET LOCAL for RLS
"""

from contextvars import ContextVar
from typing import Optional

_current_user_id: ContextVar[Optional[str]] = ContextVar(
    "current_user_id", default=None
)


def set_current_user_id(user_id: str) -> None:
    """Set the authenticated user ID for the current request context."""
    _current_user_id.set(user_id)


def get_current_user_id() -> Optional[str]:
    """Get the authenticated user ID from the current request context."""
    return _current_user_id.get()


def clear_current_user_id() -> None:
    """Clear the user ID (called at end of request or in tests)."""
    _current_user_id.set(None)
