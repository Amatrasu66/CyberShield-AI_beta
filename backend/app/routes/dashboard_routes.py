"""
Dashboard Routes.

GET /api/dashboard

Returns the authenticated user's aggregated scan metrics, recent scans,
activity feed and 12-day scan trend. ``user_id`` always comes from the verified
JWT (``get_current_user_id``); it is never read from the request body or query
string, and the user-scoped Supabase client preserves Row Level Security.
"""

from flask import Blueprint

from ..middleware import get_current_user_id, require_auth
from ..services import DashboardService
from ..utils.helpers import success_response

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.get("")
@require_auth
def dashboard():
    data = DashboardService.get_dashboard(user_id=get_current_user_id())
    return success_response(data, "Dashboard data retrieved")