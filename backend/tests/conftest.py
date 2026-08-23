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
        self.rows = {}
        self.fail_next_execute = False
        self.fail_inserts = False
        self.auth_tokens = []

    def track_auth(self, access_token=None):
        """Record the access token forwarded to a user-scoped operation."""
        self.auth_tokens.append(access_token)
        return self

    def table(self, name):
        return _FakeSupabaseTable(name, self)

    def seed(self, table, rows):
        """Seed read-only rows for ``table`` (e.g. persisted scan history)."""
        self.rows.setdefault(table, []).extend(list(rows))


class _FakeSupabaseTable:
    """Minimal query-builder stand-in supporting insert and simple selects."""

    def __init__(self, name, client):
        self._name = name
        self._client = client
        self._mode = None
        self._payload = None
        self._filters = []
        self._order = None
        self._limit = None
        self._range = None
        self._count = None
        self._on_conflict = None
        self._update_payload = None

    def insert(self, payload):
        self._mode = "insert"
        self._payload = payload
        return self

    def upsert(self, payload, on_conflict=None, **kwargs):
        self._mode = "upsert"
        self._payload = payload
        # Supabase upsert may be called with on_conflict="ip,provider"
        self._on_conflict = on_conflict or kwargs.get("on_conflict")
        return self

    def update(self, payload):
        self._mode = "update"
        self._update_payload = payload
        return self

    def select(self, columns="*", count=None, **kwargs):
        self._mode = "select"
        # ``count`` is accepted for ``select(..., count="exact")`` callers.
        if count is not None:
            self._count = count
        elif "count" in kwargs:
            self._count = kwargs["count"]
        return self

    def eq(self, column, value):
        self._filters.append((column, value))
        return self

    def order(self, column, desc=False):
        self._order = (column, desc)
        return self

    def limit(self, limit):
        self._limit = limit
        return self

    def range(self, start, end):
        self._range = (start, end)
        return self

    def execute(self):
        if self._client.fail_next_execute:
            raise ConnectionError("database unavailable")
        if self._mode == "insert":
            if self._client.fail_inserts:
                raise ConnectionError("database unavailable")
            self._client.inserts.setdefault(self._name, []).append(self._payload)
            # Make inserted rows queryable, mirroring the live database.
            row = dict(self._payload)
            row.setdefault("id", str(uuid.uuid4()))
            # Ensure default timestamps for history ordering
            if self._name == "port_scans" and "created_at" not in row:
                from datetime import datetime, timezone as _tz
                row["created_at"] = datetime.now(_tz.utc).isoformat()
            if self._name == "ip_reputation_cache" and "created_at" not in row:
                from datetime import datetime, timezone as _tz
                now = datetime.now(_tz.utc).isoformat()
                row.setdefault("created_at", now)
                row.setdefault("updated_at", now)
            self._client.rows.setdefault(self._name, []).append(row)
            return {"data": [row]}
        if self._mode == "upsert":
            if self._client.fail_inserts:
                raise ConnectionError("database unavailable")
            # Handle unique (ip, provider) for ip_reputation_cache
            rows = self._client.rows.setdefault(self._name, [])
            # Determine conflict keys
            conflict_keys = []
            if self._on_conflict:
                conflict_keys = [k.strip() for k in str(self._on_conflict).split(",")]
            else:
                # Default unique for cache
                if self._name == "ip_reputation_cache":
                    conflict_keys = ["ip", "provider"]
            # Find existing
            existing = None
            for r in rows:
                if conflict_keys and all(r.get(k) == self._payload.get(k) for k in conflict_keys):
                    existing = r
                    break
            if existing is not None:
                # Update existing in place
                existing.update(self._payload)
                # Ensure updated_at
                from datetime import datetime, timezone as _tz
                existing["updated_at"] = datetime.now(_tz.utc).isoformat()
                self._client.inserts.setdefault(self._name, []).append(self._payload)
                return {"data": [existing]}
            # Insert new
            row = dict(self._payload)
            row.setdefault("id", str(uuid.uuid4()))
            if self._name == "ip_reputation_cache":
                from datetime import datetime, timezone as _tz
                now = datetime.now(_tz.utc).isoformat()
                row.setdefault("created_at", now)
                row.setdefault("updated_at", now)
            rows.append(row)
            self._client.inserts.setdefault(self._name, []).append(self._payload)
            return {"data": [row]}
        if self._mode == "update":
            if self._client.fail_inserts:
                raise ConnectionError("database unavailable")
            rows = self._client.rows.get(self._name, [])
            matched = []
            for r in rows:
                if all(r.get(col) == val for col, val in self._filters):
                    r.update(self._update_payload or {})
                    from datetime import datetime, timezone as _tz
                    r["updated_at"] = datetime.now(_tz.utc).isoformat()
                    matched.append(r)
            return {"data": matched}
        rows = list(self._client.rows.get(self._name, []))
        for column, value in self._filters:
            rows = [r for r in rows if r.get(column) == value]
        # Preserve total before pagination for count="exact"
        total_count = len(rows)
        if self._order:
            column, desc = self._order
            rows = sorted(rows, key=lambda r: r.get(column) or "", reverse=bool(desc))
        if self._range is not None:
            start, end = self._range
            # PostgREST range is inclusive, so slice end+1
            rows = rows[start : end + 1]
        elif self._limit is not None:
            rows = rows[: self._limit]
        result = {"data": rows}
        if self._count == "exact":
            result["count"] = total_count
        return result


@pytest.fixture(autouse=True)
def fake_supabase(monkeypatch):
    """Patch the Supabase client so no test ever touches the network.

    The per-request ``get_user_supabase_client`` is replaced with the same
    in-memory fake across every service module. It records the access token
    forwarded by the service layer (``fake_supabase.auth_tokens``) so tests can
    prove JWT forwarding.
    """
    client = _FakeSupabaseClient()

    def _scoped(access_token=None):
        client.track_auth(access_token)
        return client

    # Shared fake for admin/anon as well (cache uses admin)
    def _admin():
        return client

    for module in (
        "app.services.auth_service",
        "app.services.scanner_service",
        "app.services.email_service",
        "app.services.password_service",
        "app.services.log_service",
        "app.services.report_service",
        "app.services.dashboard_service",
        "app.services.port_scanner_service",
        "app.services.ip_reputation_service",
        "app.services.ip_reputation_cache_service",
    ):
        try:
            monkeypatch.setattr(module + ".get_user_supabase_client", _scoped)
        except Exception:
            pass
        try:
            monkeypatch.setattr(module + ".get_supabase_admin_client", _admin)
        except Exception:
            pass
        try:
            monkeypatch.setattr(module + ".get_supabase_client", _admin)
        except Exception:
            pass
    # Also patch database layer directly
    try:
        monkeypatch.setattr("app.database.supabase_client.get_user_supabase_client", _scoped)
        monkeypatch.setattr("app.database.supabase_client.get_supabase_admin_client", _admin)
        monkeypatch.setattr("app.database.supabase_client.get_supabase_client", _admin)
    except Exception:
        pass
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
    IP_REPUTATION_ENABLED = False
    IP_REPUTATION_CACHE_ENABLED = False
    IP_REPUTATION_CACHE_TTL = 86400
    IP_REPUTATION_PROVIDER = "abuseipdb"
    IP_REPUTATION_API_KEY = "test-api-key"
    IP_REPUTATION_TIMEOUT = 5


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
