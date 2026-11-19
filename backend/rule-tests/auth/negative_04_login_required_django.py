# Test: negative for rule AUTH-PY-001
# Expected: should_not_trigger
# Category: auth
# Language: python
#
# Description: Django views that perform admin operations with proper
# @login_required and @permission_required decorators applied to every
# view. This file must NOT trigger AUTH-PY-001.

import json

from django.contrib.auth.decorators import login_required, permission_required
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.db import connection

from .models import User, AuditLog


@login_required
@permission_required("users.view_user", raise_exception=True)
@require_http_methods(["GET"])
def admin_users(request):
    """Return every user record -- caller must be authenticated and
    hold the users.view_user permission."""
    users = User.objects.values("id", "username", "email", "role", "date_joined")
    return JsonResponse({"success": True, "data": list(users)})


@login_required
@permission_required("users.view_user", raise_exception=True)
@require_http_methods(["GET"])
def admin_user_detail(request, user_id):
    """Return full profile for a single user."""
    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return JsonResponse({"error": "User not found"}, status=404)

    data = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
        "last_login": str(user.last_login),
    }
    return JsonResponse({"success": True, "data": data})


@login_required
@permission_required("users.change_user", raise_exception=True)
@require_http_methods(["POST"])
def admin_change_role(request, user_id):
    """Change the role of a user -- requires change_user permission."""
    body = json.loads(request.body)
    new_role = body.get("role")
    if new_role not in ("user", "moderator", "admin"):
        return JsonResponse({"error": "Invalid role"}, status=400)

    if user_id == request.user.id:
        return JsonResponse({"error": "Cannot change your own role"}, status=400)

    User.objects.filter(pk=user_id).update(role=new_role)
    AuditLog.objects.create(
        action="role_change",
        performed_by=request.user,
        target_user_id=user_id,
        new_role=new_role,
    )
    return JsonResponse({"success": True, "message": f"Role updated to {new_role}"})


@login_required
@permission_required("users.delete_user", raise_exception=True)
@require_http_methods(["DELETE"])
def admin_delete_user(request, user_id):
    """Permanently delete a user -- requires delete_user permission."""
    if user_id == request.user.id:
        return JsonResponse({"error": "Cannot delete your own account"}, status=400)

    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM user_sessions WHERE user_id = %s", [user_id])
        cursor.execute("DELETE FROM user_data WHERE user_id = %s", [user_id])
    User.objects.filter(pk=user_id).delete()
    return JsonResponse({"success": True, "message": "User deleted"})
