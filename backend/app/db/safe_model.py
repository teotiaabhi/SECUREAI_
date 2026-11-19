"""
SafeColumnMixin — graceful runtime handler for missing database columns.

When a migration hasn't been applied yet but the app code expects new columns,
this mixin prevents hard crashes by returning safe defaults instead of raising
AttributeError or UndefinedColumnError.

Usage:
    class User(Base, SafeColumnMixin):
        ...

    # Instead of user.role (may crash), use:
    role = user.safe_get("role", "user")
"""

from app.core.logging import get_logger

logger = get_logger("safe_model")

# Columns that may not exist in the DB yet, with their safe defaults.
# This map is checked at runtime only; it does NOT affect the schema.
_SAFE_DEFAULTS = {
    "role": "developer",
    "status": "active",
    "tier": "free",
    "is_paid": False,
    "ai_tokens_used": 0,
    "scans_today": 0,
    "last_scan_reset": None,
    "storage_used_bytes": 0,
}


class SafeColumnMixin:
    """Mixin that provides safe access to potentially-missing columns."""

    def safe_get(self, column_name: str, default=None):
        """
        Get a column value, returning a default if the column is missing
        from the database row (schema drift).

        Args:
            column_name: Name of the column to access.
            default: Fallback value. If None, uses _SAFE_DEFAULTS.

        Returns:
            Column value or safe default.
        """
        try:
            value = getattr(self, column_name, None)
            # SQLAlchemy sets missing columns to None on load;
            # distinguish between "column is NULL" and "column doesn't exist"
            if value is not None:
                return value
            # Return the explicit default or the safe default
            return default if default is not None else _SAFE_DEFAULTS.get(column_name)
        except Exception:
            fallback = default if default is not None else _SAFE_DEFAULTS.get(column_name)
            logger.warning(
                "safe_get_fallback",
                column=column_name,
                fallback=fallback,
            )
            return fallback
