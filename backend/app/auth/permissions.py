"""
Role-Based Access Control (RBAC) permission system.

Defines granular permissions and maps them to UserRole values.
Provides a FastAPI dependency ``require_permission`` that raises
HTTP 403 when the current user lacks the requested permissions.

Usage:
    from app.auth.permissions import require_permission, Permission

    @router.get("/admin/users")
    async def list_users(
        user = Depends(require_permission(Permission.USER_MANAGE)),
    ):
        ...
"""

import enum as stdlib_enum
from typing import Set

from fastapi import Depends, HTTPException, status

from app.auth.jwt_handler import get_current_user


class Permission(str, stdlib_enum.Enum):
    """Granular permission tokens."""

    SCAN_CREATE = "scan:create"
    SCAN_READ = "scan:read"
    SCAN_DELETE = "scan:delete"
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"
    USER_MANAGE = "user:manage"
    COMPLIANCE_READ = "compliance:read"
    DATA_EXPORT = "data:export"
    DATA_DELETE = "data:delete"


# ── Role → Permission mapping ────────────────────────────────
_ALL_PERMISSIONS: Set[Permission] = set(Permission)

ROLE_PERMISSIONS: dict[str, Set[Permission]] = {
    "user": _ALL_PERMISSIONS,
}


def _get_user_permissions(role: str) -> Set[Permission]:
    """Return the permission set for a given role string."""
    return ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS["user"])


def require_permission(*perms: Permission):
    """FastAPI dependency factory that enforces permission checks.

    Returns a Depends-compatible callable that:
    1. Authenticates the user via ``get_current_user``
    2. Resolves the user's role to a permission set
    3. Raises 403 if any of ``perms`` is missing

    Example::

        @router.get("/compliance/status")
        async def status(
            user=Depends(require_permission(Permission.COMPLIANCE_READ)),
        ):
            ...
    """

    async def _checker(user=Depends(get_current_user)):
        role_str = "user"
        if hasattr(user, "role"):
            role_val = user.role
            role_str = role_val.value if hasattr(role_val, "value") else str(role_val)

        granted = _get_user_permissions(role_str)
        missing = set(perms) - granted
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "insufficient_permissions",
                    "required": [p.value for p in perms],
                    "missing": [p.value for p in missing],
                    "role": role_str,
                },
            )
        return user

    return _checker
