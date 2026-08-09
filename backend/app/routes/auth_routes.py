"""
Authentication Routes.

POST /api/auth/register
POST /api/auth/login

Persistence is pending the Supabase integration (next phase); requests are
fully validated and then return a structured 501 response.
"""

from flask import Blueprint, current_app

from ..services import AuthService
from ..utils.helpers import success_response
from ..utils.validators import require_json, validate_string

auth_bp = Blueprint("auth", __name__)


@auth_bp.post("/register")
def register():
    data = require_json()
    email = data.get("email")
    password = data.get("password")
    validate_string(email, "email", 254, min_length=3)
    validate_string(password, "password", current_app.config.get("PASSWORD_MAX_LENGTH", 128))

    # May raise FeatureUnavailableError (501) until Supabase is wired in.
    result = AuthService.register(email, password)
    return success_response(result, "Registration successful", status_code=201)


@auth_bp.post("/login")
def login():
    data = require_json()
    email = data.get("email")
    password = data.get("password")
    validate_string(email, "email", 254, min_length=3)
    validate_string(password, "password", current_app.config.get("PASSWORD_MAX_LENGTH", 128))

    result = AuthService.login(email, password)
    return success_response(result, "Login successful")
