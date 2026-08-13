"""
Authentication Routes.

GET /api/auth/me

Signup, login, logout and session refresh are owned by Supabase Auth and called
directly from React. The Flask API exposes only the minimal auth endpoint the
backend needs: ``/me`` returns the authenticated user's profile, keyed off the
verified Supabase JWT ``sub`` claim (``auth.uid()``). The user ID is never
accepted from the request body.
"""

from flask import Blueprint

from ..middleware import get_current_user_id, require_auth
from ..services import AuthService
from ..utils.helpers import success_response

auth_bp = Blueprint("auth", __name__)


@auth_bp.get("/me")
@require_auth
def me():
    user_id = get_current_user_id()
    profile = AuthService.get_profile(user_id)
    if profile is None:
        profile = {"id": user_id}
    return success_response(profile, "Authenticated user profile")
