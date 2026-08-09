"""
Phishing Email Detector Routes.

POST /api/email/analyze
"""

from flask import Blueprint, current_app

from ..services import EmailService
from ..utils.helpers import success_response
from ..utils.validators import require_json, validate_string

email_bp = Blueprint("email", __name__)


@email_bp.post("/analyze")
def analyze_email():
    data = require_json()
    content = data.get("content")
    validate_string(content, "content", current_app.config.get("EMAIL_MAX_LENGTH", 50_000), min_length=1)
    result = EmailService.analyze_email(content)
    return success_response(result, "Email analysis completed")
