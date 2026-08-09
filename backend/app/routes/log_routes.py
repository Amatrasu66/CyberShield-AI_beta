"""
Log Analyzer Routes.

POST /api/logs/analyze
"""

from flask import Blueprint, current_app

from ..services import LogService
from ..utils.helpers import success_response
from ..utils.validators import require_json, validate_string

log_bp = Blueprint("log", __name__)


@log_bp.post("/analyze")
def analyze_logs():
    data = require_json()
    content = data.get("content")
    validate_string(content, "content", current_app.config.get("LOG_MAX_LENGTH", 500_000), min_length=1)
    log_format = data.get("log_format", "auto")
    validate_string(log_format, "log_format", 32, min_length=1)
    result = LogService.analyze_logs(content, log_format=log_format)
    return success_response(result, "Log analysis completed")
