"""
Phishing Email Detector Routes.

POST /api/email/analyze  (application/json)
    {"content": "..."}  -- analyze pasted email text

POST /api/email/analyze  (multipart/form-data)
    file=<email.pdf>     -- analyze text extracted from an uploaded email PDF

Both input methods share the exact same analyzer, response envelope, and
authentication. The extracted PDF text is fed into the same existing
email-analysis pipeline.
"""

from flask import Blueprint, current_app, request

from ..errors import ValidationError
from ..middleware import get_current_user_id, require_auth
from ..services import EmailService
from ..services.pdf_extractor import extract_pdf_email
from ..utils.helpers import success_response
from ..utils.validators import require_json, validate_string

email_bp = Blueprint("email", __name__)


@email_bp.post("/analyze")
@require_auth
def analyze_email():
    content_type = (request.content_type or "").lower()
    if request.files or content_type.startswith("multipart/"):
        file = request.files.get("file")
        if file is None or not file.filename:
            raise ValidationError("A PDF file is required", details={"field": "file"})
        content = extract_pdf_email(file, current_app.config)
    else:
        data = require_json()
        content = data.get("content")
        validate_string(content, "content", current_app.config.get("EMAIL_MAX_LENGTH", 50_000), min_length=1)
    result = EmailService.analyze_email(content, user_id=get_current_user_id())
    return success_response(result, "Email analysis completed")
