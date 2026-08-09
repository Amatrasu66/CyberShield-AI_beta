"""
System routes.

GET /api/health
GET /api/version
"""

from datetime import datetime, timezone

from flask import Blueprint, current_app

from ..utils.helpers import success_response

system_bp = Blueprint("system", __name__)


@system_bp.get("/health")
def health():
    """Liveness check. Reports service status without leaking internals."""
    cfg = current_app.config
    payload = {
        "status": "ok",
        "service": cfg.get("APP_NAME", "CyberShield AI API"),
        "version": cfg.get("API_VERSION", "1.0"),
        "environment": cfg.get("ENVIRONMENT", "development"),
        "time": datetime.now(timezone.utc).isoformat(),
        "dependencies": {
            "database": "configured" if cfg.get("SUPABASE_URL") else "not_configured",
            "database_connected": False,
            "ml_models": "not_loaded",
        },
    }
    return success_response(payload, "Service is healthy")


@system_bp.get("/version")
def version():
    """Return backend and API version information."""
    cfg = current_app.config
    payload = {
        "name": cfg.get("APP_NAME", "CyberShield AI API"),
        "version": cfg.get("API_VERSION", "1.0"),
        "api_url_prefix": cfg.get("API_URL_PREFIX", "/api"),
        "environment": cfg.get("ENVIRONMENT", "development"),
    }
    return success_response(payload, "Version information")
