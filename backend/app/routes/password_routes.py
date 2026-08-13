"""
Password Strength Analyzer Routes.

POST /api/password/analyze
"""

from flask import Blueprint, current_app

from ..middleware import get_current_user_id, require_auth
from ..services import PasswordService
from ..utils.helpers import success_response
from ..utils.validators import require_json, validate_password_input

password_bp = Blueprint("password", __name__)


@password_bp.post("/analyze")
@require_auth
def analyze_password():
    data = require_json()
    password = data.get("password")
    validate_password_input(password, max_length=current_app.config.get("PASSWORD_MAX_LENGTH", 4096))
    result = PasswordService.analyze_password(password, user_id=get_current_user_id())
    return success_response(result, "Password analysis completed")
