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

    CORS(
        app,
        resources={r"/api/*": {"origins": app.config.get("CORS_ORIGINS")}},
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
