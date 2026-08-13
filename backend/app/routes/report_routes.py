"""
Security Audit Reports Routes.

GET /api/reports
POST /api/reports/generate

Reports are generated from the authenticated user's Supabase scan data, stored
in ``public.reports``, and their PDFs uploaded to private Storage with signed
access URLs. The user ID always comes from the verified JWT (``auth.uid()``).
"""

from flask import Blueprint

from ..middleware import get_current_user_id, require_auth
from ..services import ReportService
from ..utils.helpers import success_response
from ..utils.validators import require_json

report_bp = Blueprint("report", __name__)


@report_bp.get("")
@require_auth
def list_reports():
    reports = ReportService.list_reports(user_id=get_current_user_id())
    return success_response(reports, "Reports retrieved", meta={"count": len(reports)})


@report_bp.post("/generate")
@require_auth
def generate_report():
    data = require_json()
    result = ReportService.generate_report(data, user_id=get_current_user_id())
    return success_response(result, "Report generated", status_code=201)
