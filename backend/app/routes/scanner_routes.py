"""
Website Security Scanner Routes.

POST /api/scanner/website
"""

from flask import Blueprint, current_app

from ..services import ScannerService
from ..utils.helpers import success_response
from ..utils.validators import require_json, validate_url

scanner_bp = Blueprint("scanner", __name__)


@scanner_bp.post("/website")
def scan_website():
    data = require_json()
    url = data.get("url")
    validate_url(url, max_length=current_app.config.get("URL_MAX_LENGTH", 2048))
    result = ScannerService.scan_website(url)
    return success_response(result, "Website scan completed")
