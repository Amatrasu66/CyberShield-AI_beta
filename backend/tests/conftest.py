"""
Shared pytest fixtures.

Tests create a fresh app per test using the application factory with a testing
config. No database or ML models are required.

Protected-route tests authenticate with real RS256 JWTs signed by an in-test
RSA key; JWKS fetching is replaced with a fake ``PyJWKClient`` so no network
is needed.
"""

import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app import create_app
from app.config.settings import Config
from app.utils import security as security_utils

TEST_SUPABASE_URL = "https://abcxyz.supabase.co"
TEST_AUDIENCE = "authenticated"


class _FakeSigningKey:
    def __init__(self, key):
        self.key = key


class _FakeSupabaseClient:
    """Deterministic in-memory stand-in for the Supabase client."""

    def __init__(self):
        self.inserts = {}
        self.fail_next_execute = False

    def table(self, name):
        return _FakeSupabaseTable(name, self)


class _FakeSupabaseTable:
    def __init__(self, name, client):
        self._name = name
        self._client = client

    def insert(self, payload):
        self._payload = payload
        return self

    def execute(self):
        if self._client.fail_next_execute:
            raise ConnectionError("database unavailable")
        self._client.inserts.setdefault(self._name, []).append(self._payload)
        return {"data": [self._payload]}


@pytest.fixture(autouse=True)
def fake_supabase(monkeypatch):
    """Patch the Supabase client so no test ever touches the network."""
    client = _FakeSupabaseClient()
    monkeypatch.setattr(
        "app.services.scanner_service.get_supabase_client", lambda: client
    )
    monkeypatch.setattr(
        "app.services.email_service.get_supabase_client", lambda: client
    )
    monkeypatch.setattr(
        "app.services.password_service.get_supabase_client", lambda: client
    )
    monkeypatch.setattr(
        "app.services.log_service.get_supabase_client", lambda: client
    )
    return client


class _FakeJWKClient:
    """Stands in for ``jwt.PyJWKClient``; returns the injected public key."""

    public_key = None

    def __init__(self, *args, **kwargs):
        pass

    def get_signing_key_from_jwt(self, token):
        if _FakeJWKClient.public_key is None:
            raise AssertionError("_FakeJWKClient.public_key was not injected")
        return _FakeSigningKey(_FakeJWKClient.public_key)


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


@pytest.fixture(scope="session")
def _jwt_signing_keys():
    """In-test RSA key pair used to sign and verify test JWTs."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_key, public_pem


@pytest.fixture()
def auth_user_id():
    """Stable UUID identifying the authenticated user in a test."""
    return str(uuid.uuid4())


@pytest.fixture()
def make_auth_token(_jwt_signing_keys):
    """Factory producing valid RS256 Supabase-style access tokens."""

    def _make(sub: str = None) -> str:
        now = datetime.now(timezone.utc)
        claims = {
            "sub": sub or str(uuid.uuid4()),
            "iss": f"{TEST_SUPABASE_URL}/auth/v1",
            "aud": TEST_AUDIENCE,
            "iat": now - timedelta(seconds=60),
            "exp": now + timedelta(hours=1),
            "role": "authenticated",
            "email": "user@example.com",
        }
        return jwt.encode(claims, _jwt_signing_keys[0], algorithm="RS256")

    return _make


@pytest.fixture()
def auth_token(make_auth_token, auth_user_id):
    """A valid access token for the test's authenticated user."""
    return make_auth_token(auth_user_id)


@pytest.fixture()
def auth_headers(auth_token):
    """Authorization header carrying a valid access token."""
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture(autouse=True)
def _jwt_auth_harness(app, monkeypatch, _jwt_signing_keys):
    """Configure deterministic Supabase JWT verification for every test.

    Pins the Supabase configuration and replaces the JWKS client with a fake so
    any test can authenticate simply by passing ``auth_headers``.
    """
    app.config["SUPABASE_URL"] = TEST_SUPABASE_URL
    app.config["SUPABASE_JWKS_URL"] = ""
    app.config["SUPABASE_JWT_ISSUER"] = ""
    app.config["SUPABASE_JWT_ALGORITHM"] = "RS256"
    app.config["SUPABASE_JWT_AUDIENCE"] = TEST_AUDIENCE
    _, public_pem = _jwt_signing_keys
    _FakeJWKClient.public_key = public_pem
    monkeypatch.setattr(security_utils, "PyJWKClient", _FakeJWKClient)


@pytest.fixture(autouse=True)
def _clean_report_store():
    """Reset the in-memory report store before each test."""
    from app.services.report_service import ReportService

    ReportService.clear_reports()
    yield
