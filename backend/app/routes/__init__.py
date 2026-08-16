"""
Routes package: blueprint definitions and registration.

Blueprints are registered under ``API_URL_PREFIX`` (default ``/api``).
Versioning is handled via the ``/api/version`` endpoint and the ``API_VERSION``
configuration value rather than URL path segments, matching the documented API.
"""

from .auth_routes import auth_bp
from .crypto_routes import crypto_bp
from .dashboard_routes import dashboard_bp
from .email_routes import email_bp
from .log_routes import log_bp
from .password_routes import password_bp
from .report_routes import report_bp
from .scanner_routes import scanner_bp
from .sql_routes import sql_bp
from .system_routes import system_bp


def register_blueprints(app):
    """Register all API blueprints on the Flask app."""
    prefix = app.config.get("API_URL_PREFIX", "/api")
    app.register_blueprint(system_bp, url_prefix=prefix)
    app.register_blueprint(auth_bp, url_prefix=f"{prefix}/auth")
    app.register_blueprint(dashboard_bp, url_prefix=f"{prefix}/dashboard")
    app.register_blueprint(scanner_bp, url_prefix=f"{prefix}/scanner")
    app.register_blueprint(email_bp, url_prefix=f"{prefix}/email")
    app.register_blueprint(password_bp, url_prefix=f"{prefix}/password")
    app.register_blueprint(log_bp, url_prefix=f"{prefix}/logs")
    app.register_blueprint(crypto_bp, url_prefix=f"{prefix}/crypto")
    app.register_blueprint(sql_bp, url_prefix=f"{prefix}/sql")
    app.register_blueprint(report_bp, url_prefix=f"{prefix}/reports")


__all__ = ["register_blueprints"]
