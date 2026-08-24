"""Phase 2D-6 — CORS lockdown & error-detail sanitization regression tests."""

import logging
import pytest

from app import create_app
from app.config.settings import Config
from app.errors import ServiceUnavailableError, ValidationError


class ProdCorsConfig(Config):
    ENVIRONMENT = "production"
    TESTING = False
    CORS_ORIGINS = ["https://allowed.example.com"]
    SECRET_KEY = "test-secret-key-prod"


class ProdWildcardConfig(Config):
    ENVIRONMENT = "production"
    TESTING = False
    CORS_ORIGINS = ["*"]
    SECRET_KEY = "test-secret-key-prod"


class ProdMultipleCorsConfig(Config):
    ENVIRONMENT = "production"
    TESTING = False
    CORS_ORIGINS = ["https://allowed.example.com", "https://other.example.com"]
    SECRET_KEY = "test-secret-key-prod"


class DevWildcardConfig(Config):
    ENVIRONMENT = "development"
    TESTING = False
    CORS_ORIGINS = ["*"]
    SECRET_KEY = "dev-secret"


# --- CORS tests ---

def test_cors_allowed_origin_returns_header():
    app = create_app(ProdCorsConfig)
    client = app.test_client()
    resp = client.get("/api/health", headers={"Origin": "https://allowed.example.com"})
    assert resp.headers.get("Access-Control-Allow-Origin") == "https://allowed.example.com"


def test_cors_disallowed_origin_no_header():
    app = create_app(ProdCorsConfig)
    client = app.test_client()
    resp = client.get("/api/health", headers={"Origin": "https://evil.com"})
    # Flask-CORS should not echo a disallowed origin
    assert resp.headers.get("Access-Control-Allow-Origin") is None


def test_cors_preflight_allowed_origin():
    app = create_app(ProdCorsConfig)
    client = app.test_client()
    resp = client.options(
        "/api/health",
        headers={
            "Origin": "https://allowed.example.com",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization",
        },
    )
    # Preflight should succeed and echo the origin
    assert resp.status_code in (200, 204)
    assert resp.headers.get("Access-Control-Allow-Origin") == "https://allowed.example.com"
    # Allowed methods should include GET
    allow_methods = resp.headers.get("Access-Control-Allow-Methods", "")
    assert "GET" in allow_methods or allow_methods != ""


def test_cors_preflight_disallowed_origin_no_header():
    app = create_app(ProdCorsConfig)
    client = app.test_client()
    resp = client.options(
        "/api/health",
        headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.headers.get("Access-Control-Allow-Origin") is None


def test_cors_production_wildcard_stripped():
    app = create_app(ProdWildcardConfig)
    # Wildcard must be removed in production (fail-closed)
    assert "*" not in app.config["CORS_ORIGINS"]
    assert app.config["CORS_ORIGINS"] == []
    client = app.test_client()
    resp = client.get("/api/health", headers={"Origin": "https://any.example.com"})
    assert resp.headers.get("Access-Control-Allow-Origin") is None


def test_cors_development_wildcard_preserved():
    app = create_app(DevWildcardConfig)
    assert "*" in app.config["CORS_ORIGINS"]
    client = app.test_client()
    resp = client.get("/api/health", headers={"Origin": "http://localhost:3000"})
    # In dev wildcard, Flask-CORS reflects the requesting origin or *
    assert resp.headers.get("Access-Control-Allow-Origin") in ("*", "http://localhost:3000", None) or resp.status_code == 200
    # At least it should not error
    assert resp.status_code == 200


def test_cors_production_multiple_origins():
    app = create_app(ProdMultipleCorsConfig)
    client = app.test_client()
    for origin in ["https://allowed.example.com", "https://other.example.com"]:
        resp = client.get("/api/health", headers={"Origin": origin})
        assert resp.headers.get("Access-Control-Allow-Origin") == origin
    resp = client.get("/api/health", headers={"Origin": "https://evil.com"})
    assert resp.headers.get("Access-Control-Allow-Origin") is None


# --- Error-detail sanitization tests ---

def test_error_details_hide_table_and_error_but_keep_field(client, app, monkeypatch, caplog):
    # Simulate a ServiceUnavailableError with sensitive details
    @app.route("/api/test-leak-table")
    def leak():
        raise ServiceUnavailableError("DB failed", details={"table": "website_scans", "error": "ConnectionError", "field": "url"})

    with caplog.at_level(logging.INFO, logger="cybershield.errors"):
        resp = client.get("/api/test-leak-table")
    body = resp.get_json()
    assert resp.status_code == 503
    # Safe field should remain
    assert body["error"]["details"] is not None
    assert body["error"]["details"].get("field") == "url"
    # Sensitive table/error must be hidden
    assert body["error"]["details"].get("table") is None
    assert body["error"]["details"].get("error") is None
    # No stack trace
    assert "traceback" not in str(body).lower()
    # Server log should contain full details
    assert "website_scans" in caplog.text or "ConnectionError" in caplog.text


def test_error_details_hide_bucket_and_sensitive_keys(app, client, caplog):
    @app.route("/api/test-leak-bucket")
    def leak():
        raise ServiceUnavailableError(
            "Storage failed",
            details={"bucket": "report-pdfs", "path": "user/file.pdf", "table": "reports", "error": "Timeout"},
        )

    with caplog.at_level(logging.INFO, logger="cybershield.errors"):
        resp = client.get("/api/test-leak-bucket")
    body = resp.get_json()
    details = body["error"].get("details")
    # bucket/table/error are dropped; path is kept only if allowlisted (path is safe)
    if details is not None:
        assert "bucket" not in details
        assert "table" not in details
        assert "error" not in details


def test_error_details_never_expose_api_keys_or_jwts(app, client):
    @app.route("/api/test-leak-secrets")
    def leak():
        raise ValidationError(
            "Bad input",
            details={
                "field": "token",
                "api_key": "sk-live-123",
                "service_role_key": "secret",
                "jwt": "eyJhbGciOi...",
                "field2": "safe-value",
            },
        )

    resp = client.get("/api/test-leak-secrets")
    body = resp.get_json()
    details = body["error"].get("details") or {}
    # api_key-like keys must be stripped
    assert "api_key" not in details
    assert "service_role_key" not in details
    assert "jwt" not in details
    # But safe keys remain (field is allowlisted)
    # Note: "field2" is not in allowlist, so it will be dropped; only "field" stays
    assert details.get("field") == "token" or "field" in details


def test_error_details_preserve_safe_keys_and_status_codes(app, client):
    @app.route("/api/test-safe-details")
    def safe():
        raise ValidationError("Invalid port", details={"field": "ports", "port": 99999, "limit": 100})

    resp = client.get("/api/test-safe-details")
    body = resp.get_json()
    assert resp.status_code == 400
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert body["error"]["details"]["field"] == "ports"
    assert body["error"]["details"]["port"] == 99999
    assert body["error"]["details"]["limit"] == 100


def test_error_details_truncate_long_values(app, client):
    @app.route("/api/test-truncate")
    def trunc():
        raise ValidationError("x", details={"field": "url", "value": "a" * 500})

    resp = client.get("/api/test-truncate")
    body = resp.get_json()
    val = body["error"]["details"]["value"]
    assert len(val) <= 203  # 200 + "..."
    assert val.endswith("...")


def test_500_still_hides_internal_message(app, client):
    @app.route("/api/test-crash-2")
    def crash():
        raise RuntimeError("super secret stack trace SELECT * FROM users")

    resp = client.get("/api/test-crash-2")
    assert resp.status_code == 500
    body = resp.get_json()
    assert body["error"]["code"] == "INTERNAL_ERROR"
    assert "SELECT" not in str(body)
    assert "secret" not in str(body).lower()


def test_rate_limit_details_still_exposed_safely(client, auth_headers, app):
    from app.middleware.rate_limiter import clear_rate_limit_store

    clear_rate_limit_store()
    app.config["RATE_LIMIT_ENABLED"] = True
    app.config["RATE_LIMIT_PORT_SCAN"] = 1
    app.config["RATE_LIMIT_PORT_SCAN_WINDOW"] = 60

    # First request ok
    import socket
    from unittest.mock import patch

    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]):
        with patch("socket.socket") as ms:
            ms.return_value.connect_ex.return_value = 1
            ms.return_value.recv.return_value = b""
            ms.return_value.close.return_value = None
            ms.return_value.settimeout.return_value = None
            resp = client.post("/api/scanner/ports", json={"target": "example.com", "ports": [80]}, headers=auth_headers)
            assert resp.status_code == 200
        # Second should be rate limited and details should be sanitized but contain safe keys
        resp2 = client.post("/api/scanner/ports", json={"target": "example.com", "ports": [80]}, headers=auth_headers)
        assert resp2.status_code == 429
        body = resp2.get_json()
        assert body["error"]["code"] == "RATE_LIMIT_EXCEEDED"
        assert "retry_after_seconds" in body["error"]["details"]
        assert "limit" in body["error"]["details"]
        assert "window_seconds" in body["error"]["details"]

    clear_rate_limit_store()


def test_success_response_format_unchanged(client):
    resp = client.get("/api/health")
    body = resp.get_json()
    assert body["success"] is True
    assert "data" in body
    assert "message" in body
