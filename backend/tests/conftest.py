"""
Shared pytest fixtures.

Tests create a fresh app per test using the application factory with a testing
config. No database or ML models are required.
"""

import pytest

from app import create_app
from app.config.settings import Config


class TestingConfig(Config):
    """Deterministic, test-friendly configuration."""

    ENVIRONMENT = "testing"
    TESTING = True
    DEBUG = False
    REQUEST_LOG_ENABLED = False
    SECRET_KEY = "test-secret-key-0123456789abcdef0123456789abcdef"
    CORS_ORIGINS = ["http://localhost:3000"]
    SCANNER_ALLOW_PRIVATE_ADDRESSES = True
    PASSWORD_MAX_LENGTH = 64
    EMAIL_MAX_LENGTH = 1000
    LOG_MAX_LENGTH = 2000
    CRYPTO_MAX_INPUT_LENGTH = 500


@pytest.fixture()
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        yield app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def _clean_report_store():
    """Reset the in-memory report store before each test."""
    from app.services.report_service import ReportService

    ReportService.clear_reports()
    yield
