"""
Authentication Routes.

GET /api/auth/me
PATCH /api/auth/me

Signup, login, logout and session refresh are owned by Supabase Auth and called
directly from React. The Flask API exposes only the minimal auth endpoints the
backend needs. Identity always comes from the verified Supabase JWT ``sub``
claim (``auth.uid()``); user IDs are never accepted from the request body.

PATCH /api/auth/me allows the authenticated user to update their own
``full_name``. Only ``full_name`` is writable — ``role`` and ``email`` remain
read-only to prevent self-escalation and are enforced both by validation and RLS.
"""

from flask import Blueprint, request

from ..errors import ValidationError
from ..middleware import get_current_user_id, require_auth
from ..services import AuthService
from ..utils.helpers import success_response

auth_bp = Blueprint("auth", __name__)

# Fields that must NEVER be self-updated via this endpoint
_FORBIDDEN_PROFILE_FIELDS = {"role", "email", "id", "user_id", "created_at", "updated_at"}


@auth_bp.get("/me")
@require_auth
def me():
    user_id = get_current_user_id()
    profile = AuthService.get_profile(user_id)
    if profile is None:
        profile = {"id": user_id}
    return success_response(profile, "Authenticated user profile")


@auth_bp.patch("/me")
@auth_bp.put("/me")
@require_auth
def update_me():
    """Update the authenticated user's own profile.

    Security: user_id is derived from the verified JWT ``sub`` claim; any
    ``id``/``user_id`` in the body is ignored and ``role``/``email`` writes
    are explicitly rejected with 400.
    """
    user_id = get_current_user_id()

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValidationError("Request body must be a JSON object", details={"field": "body"})

    # Reject attempts to set forbidden fields (prevents self-escalation even if RLS would block)
    forbidden_present = [k for k in data.keys() if k in _FORBIDDEN_PROFILE_FIELDS]
    if forbidden_present:
        raise ValidationError(
            f"Field(s) not allowed: {', '.join(sorted(forbidden_present))}",
            details={"field": ", ".join(sorted(forbidden_present)), "forbidden": sorted(forbidden_present)},
        )

    # Also reject any user_id variant keys silently supplied to avoid confusion
    if "user_id" in data or "id" in data:
        raise ValidationError("Cannot change user id", details={"field": "id"})

    if "full_name" not in data:
        raise ValidationError("'full_name' is required", details={"field": "full_name"})

    updated = AuthService.update_profile(user_id, data["full_name"])
    return success_response(updated, "Profile updated")
