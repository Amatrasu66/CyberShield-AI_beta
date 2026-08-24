"""
CyberShield AI Flask application factory.

Creates and configures the Flask app: configuration, CORS, logging, centralized
error handling, HTTP security headers, request logging, and blueprint
registration.

The factory intentionally does NOT connect Supabase or load ML models; those
subsystems are wired in during later phases.
"""

import logging

from flask import Flask
from flask_cors import CORS

from .config import get_config
from .middleware import (
    register_error_handlers,
    register_request_logging,
    register_security_headers,
)
from .routes import register_blueprints


def configure_logging(app: Flask):
    """Configure the root application logger."""
    level = getattr(logging, str(app.config.get("LOG_LEVEL", "INFO")).upper(), logging.INFO)
    app.logger.setLevel(level)
    app.logger.handlers.clear()
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s [%(name)s] %(message)s"
        )
    )
    app.logger.addHandler(handler)
    app.logger.propagate = False


def _resolve_cors_origins(app: Flask) -> list:
    """Resolve effective CORS origins, stripping wildcard in production.

    - Development / testing: wildcard ``*`` is allowed for convenience.
    - Production: wildcard is removed and a warning is logged; at least one
      explicit origin must be configured via ``CORS_ORIGINS`` or all
      cross-origin requests will be denied (fail-closed). This preserves
      ``CORS_ORIGINS`` configurability while ensuring production never
      relies on ``*``.
    """
    raw = app.config.get("CORS_ORIGINS", "*")
    if isinstance(raw, str):
        origins = [o.strip() for o in raw.split(",") if o.strip()]
    elif isinstance(raw, (list, tuple)):
        origins = [str(o).strip() for o in raw if str(o).strip()]
    else:
        origins = []
    env = str(app.config.get("ENVIRONMENT", "development")).lower()
    if env == "production" and "*" in origins:
        app.logger.warning(
            "CORS wildcard '*' is not allowed in production; removing it. "
            "Configure CORS_ORIGINS with explicit origins."
        )
        origins = [o for o in origins if o != "*"]
        if not origins:
            app.logger.error(
                "No explicit CORS_ORIGINS configured for production; "
                "all cross-origin API requests will be denied."
            )
        app.config["CORS_ORIGINS"] = origins
    return origins


def create_app(config_object=None, **config_overrides):
    """Application factory.

    Args:
        config_object: optional Config class (defaults to ``Config``).
        **config_overrides: additional config values applied after the class
            (used by tests to override settings per-app).
    """
    Config = config_object or get_config()

    app = Flask(__name__)
    app.config.from_mapping(Config.as_flask_mapping())
    app.config.update(**config_overrides)

    effective_origins = _resolve_cors_origins(app)
    CORS(
        app,
        resources={r"/api/*": {"origins": effective_origins}},
        supports_credentials=app.config.get("CORS_SUPPORTS_CREDENTIALS", False),
    )

    configure_logging(app)
    register_error_handlers(app)
    register_security_headers(app)
    register_request_logging(app)
    register_blueprints(app)

    app.logger.info(
        "Started %s (version %s, environment %s)",
        app.config.get("APP_NAME"),
        app.config.get("API_VERSION"),
        app.config.get("ENVIRONMENT"),
    )

    return app
