"""
Phishing Email Detector Routes.

POST /api/email/analyze
"""

from flask import Blueprint, current_app

from ..middleware import get_current_user_id, require_auth
from ..services import EmailService
from ..utils.helpers import success_response
from ..utils.validators import require_json, validate_string

email_bp = Blueprint("email", __name__)


@email_bp.post("/analyze")
@require_auth
def analyze_email():
    data = require_json()
    content = data.get("content")
    validate_string(content, "content", current_app.config.get("EMAIL_MAX_LENGTH", 50_000), min_length=1)
    result = EmailService.analyze_email(content, user_id=get_current_user_id())
    return success_response(result, "Email analysis completed")
