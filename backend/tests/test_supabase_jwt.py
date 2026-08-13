"""Tests for Supabase JWT verification and the ``require_auth`` middleware.

JWKS fetching is mocked with a fake ``PyJWKClient`` so no network is needed;
tokens are real RS256 JWTs generated with an in-test RSA key.
"""

import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import request

from app.errors import UnauthorizedError
from app.middleware import get_bearer_token, get_current_user_id, require_auth
from app.utils import security as security_utils
from app.utils.helpers import success_response

SUPABASE_URL = "https://abcxyz.supabase.co"
AUDIENCE = "authenticated"


@pytest.fixture()
def signing_keys():
    """In-test RSA key pair used to sign and verify test JWTs."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_key, public_pem


class _FakeSigningKey:
    def __init__(self, key):
        self.key = key


class _FakeJWKClient:
    """Stands in for ``jwt.PyJWKClient``; returns the injected public key."""

    public_key = None

    def __init__(self, *args, **kwargs):
        pass

    def get_signing_key_from_jwt(self, token):
        if _FakeJWKClient.public_key is None:
            raise AssertionError("_FakeJWKClient.public_key was not injected")
        return _FakeSigningKey(_FakeJWKClient.public_key)


_UNSET = object()


def _make_token(
    private_key,
    *,
    sub=_UNSET,
    issuer=_UNSET,
    audience=AUDIENCE,
    expire_in_seconds=3600,
    issued_seconds_ago=60,
    **overrides,
):
    """Build an RS256-signed Supabase-style access token.

    Pass ``sub=None``/``issuer=None`` to omit that claim; pass a string to set
    it; omit the argument entirely to keep the default valid value.
    """
    now = datetime.now(timezone.utc)
    claims = {
        "sub": str(uuid.uuid4()),
        "iss": f"{SUPABASE_URL}/auth/v1",
        "aud": audience,
        "iat": now - timedelta(seconds=issued_seconds_ago),
        "exp": now + timedelta(seconds=expire_in_seconds),
        "role": "authenticated",
        "email": "user@example.com",
    }
    for name, value in (("sub", sub), ("iss", issuer)):
        if value is _UNSET:
            continue
        if value is None:
            claims.pop(name)
        else:
            claims[name] = value
    for name, value in overrides.items():
        if value is None:
            claims.pop(name, None)
        else:
            claims[name] = value
    return jwt.encode(claims, private_key, algorithm="RS256")


@pytest.fixture()
def supabase_config(app):
    """Pin deterministic Supabase JWT configuration on the test app."""
    app.config["SUPABASE_URL"] = SUPABASE_URL
    app.config["SUPABASE_JWKS_URL"] = ""
    app.config["SUPABASE_JWT_ISSUER"] = ""
    app.config["SUPABASE_JWT_ALGORITHM"] = "RS256"
    app.config["SUPABASE_JWT_AUDIENCE"] = AUDIENCE
    return app


@pytest.fixture()
def verifier(app, monkeypatch, signing_keys, supabase_config):
    """Patch the JWKS client and return the private key for signing."""
    _, public_pem = signing_keys
    _FakeJWKClient.public_key = public_pem
    monkeypatch.setattr(security_utils, "PyJWKClient", _FakeJWKClient)
    return signing_keys[0]


@pytest.fixture()
def protected_client(app, client, monkeypatch, signing_keys, supabase_config):
    """Client with a ``@require_auth`` protected route registered."""
    _, public_pem = signing_keys
    _FakeJWKClient.public_key = public_pem
    monkeypatch.setattr(security_utils, "PyJWKClient", _FakeJWKClient)

    @require_auth
    def protected_view():
        return success_response(
            {
                "user_id": get_current_user_id(),
                "sub": getattr(request, "auth", {}).get("sub"),
            },
            "Protected resource",
        )

    app.add_url_rule("/api/_tests/protected", "test_protected", protected_view)
    return client, signing_keys[0]


class TestDecodeSupabaseToken:
    def test_valid_token_returns_claims(self, app, verifier):
        subject = str(uuid.uuid4())
        claims = security_utils.decode_supabase_token(_make_token(verifier, sub=subject))
        assert claims["sub"] == subject
        assert claims["iss"] == f"{SUPABASE_URL}/auth/v1"
        assert claims["aud"] == AUDIENCE
        assert "exp" in claims
        assert claims["role"] == "authenticated"

    def test_expired_token_rejected(self, app, verifier):
        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token(
                _make_token(verifier, expire_in_seconds=-10)
            )

    def test_wrong_audience_rejected(self, app, verifier):
        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token(
                _make_token(verifier, audience="service_role")
            )

    def test_wrong_issuer_rejected(self, app, verifier):
        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token(
                _make_token(verifier, issuer="https://evil.example.com/auth/v1")
            )

    def test_missing_sub_rejected(self, app, verifier):
        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token(_make_token(verifier, sub=None))

    def test_non_uuid_sub_rejected(self, app, verifier):
        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token(_make_token(verifier, sub="not-a-uuid"))

    def test_missing_exp_rejected(self, app, verifier):
        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token(_make_token(verifier, exp=None))

    def test_bad_signature_rejected(self, app, verifier):
        other_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token(_make_token(other_private))

    def test_garbage_token_rejected(self, app, verifier):
        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token("not.a.jwt")

    def test_missing_configuration_rejected(self, app):
        app.config["SUPABASE_URL"] = ""
        app.config["SUPABASE_JWKS_URL"] = ""
        app.config["SUPABASE_JWT_ISSUER"] = ""
        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token("ignored.value")


class TestGetBearerToken:
    def test_returns_token(self, app):
        with app.test_request_context(headers={"Authorization": "Bearer abc.def.ghi"}):
            assert get_bearer_token() == "abc.def.ghi"

    def test_missing_header_raises(self, app):
        with app.test_request_context():
            with pytest.raises(UnauthorizedError):
                get_bearer_token()

    def test_wrong_scheme_raises(self, app):
        with app.test_request_context(headers={"Authorization": "Basic abc"}):
            with pytest.raises(UnauthorizedError):
                get_bearer_token()


class TestRequireAuthMiddleware:
    def test_valid_token_authorized(self, protected_client):
        client, private_key = protected_client
        subject = str(uuid.uuid4())
        token = _make_token(private_key, sub=subject)
        response = client.get(
            "/api/_tests/protected",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        body = response.get_json()
        assert body["success"] is True
        assert body["data"]["user_id"] == subject
        assert body["data"]["sub"] == subject

    def test_missing_token_returns_401(self, protected_client):
        client, _ = protected_client
        response = client.get("/api/_tests/protected")
        assert response.status_code == 401
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "UNAUTHORIZED"

    def test_non_bearer_header_returns_401(self, protected_client):
        client, _ = protected_client
        response = client.get(
            "/api/_tests/protected",
            headers={"Authorization": "Basic abc"},
        )
        assert response.status_code == 401

    def test_malformed_token_returns_401(self, protected_client):
        client, _ = protected_client
        response = client.get(
            "/api/_tests/protected",
            headers={"Authorization": "Bearer not.a.jwt"},
        )
        assert response.status_code == 401

    def test_expired_token_returns_401(self, protected_client):
        client, private_key = protected_client
        token = _make_token(private_key, expire_in_seconds=-10)
        response = client.get(
            "/api/_tests/protected",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 401

    def test_invalid_claims_return_401(self, protected_client):
        client, private_key = protected_client
        for token in (
            _make_token(private_key, audience="service_role"),
            _make_token(private_key, issuer="https://evil.example.com/auth/v1"),
            _make_token(private_key, sub="not-a-uuid"),
            _make_token(private_key, sub=None),
        ):
            response = client.get(
                "/api/_tests/protected",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 401, token[:20]

    def test_forged_signature_returns_401(self, protected_client):
        client, _ = protected_client
        other_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        forged = _make_token(other_private)
        response = client.get(
            "/api/_tests/protected",
            headers={"Authorization": f"Bearer {forged}"},
        )
        assert response.status_code == 401

    def test_health_and_version_remain_public(self, client):
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/version").status_code == 200
