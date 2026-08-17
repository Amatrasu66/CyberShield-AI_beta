"""
Password Strength Analyzer Routes.

POST /api/password/analyze
POST /api/password/generate
"""

from flask import Blueprint, current_app

from ..middleware import get_current_user_id, require_auth
from ..services import PasswordService, PasswordGenerator
from ..utils.helpers import success_response, error_response
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


@password_bp.post("/generate")
@require_auth
def generate_password():
    data = require_json()
    gen_type = data.get("type")

    if gen_type == "passphrase":
        words = data.get("words", 5)
        if not isinstance(words, int):
            return error_response("words must be an integer", status_code=400, code="VALIDATION_ERROR")
        if not 4 <= words <= 6:
            return error_response("words must be between 4 and 6", status_code=400, code="VALIDATION_ERROR")
        delimiter = data.get("delimiter", "-")
        result = PasswordGenerator.generate_passphrase(words=words, delimiter=delimiter)

    elif gen_type == "random":
        length = data.get("length", 20)
        if not isinstance(length, int):
            return error_response("length must be an integer", status_code=400, code="VALIDATION_ERROR")
        if not 8 <= length <= 64:
            return error_response("length must be between 8 and 64", status_code=400, code="VALIDATION_ERROR")
        result = PasswordGenerator.generate_random_password(length=length)

    else:
        return error_response("type must be 'passphrase' or 'random'", status_code=400, code="VALIDATION_ERROR")

    return success_response(result, "Password generated successfully")
