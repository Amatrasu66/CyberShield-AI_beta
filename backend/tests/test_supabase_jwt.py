"""Tests for Supabase JWT verification and the ``require_auth`` middleware.

JWKS fetching is mocked with a fake ``PyJWKClient`` so no network is needed;
tokens are real RS256 and ES256 JWTs generated with in-test RSA and EC P-256
keys.
"""

import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
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
    algorithm="RS256",
    kid=None,
    **overrides,
):
    """Build a signed Supabase-style access token.

    Pass ``sub=None``/``issuer=None`` to omit that claim; pass a string to set
    it; omit the argument entirely to keep the default valid value. ``algorithm``
    selects the signing algorithm (``RS256`` or ``ES256``) and ``kid``, when
    given, is attached to the token header for JWKS key selection.
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
    headers = {"kid": kid} if kid else None
    return jwt.encode(claims, private_key, algorithm=algorithm, headers=headers)


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


@pytest.fixture()
def es256_signing_keys():
    """In-test EC P-256 key pair used to sign and verify ES256 test JWTs."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_key, public_pem


class _FakeJWKClientByKid:
    """Fake JWK client that selects the signing key by JWT ``kid``."""

    keys_by_kid = {}

    def __init__(self, *args, **kwargs):
        pass

    def get_signing_key_from_jwt(self, token):
        kid = jwt.get_unverified_header(token).get("kid")
        if not kid or kid not in _FakeJWKClientByKid.keys_by_kid:
            raise jwt.exceptions.InvalidKeyError("no signing key for kid")
        return _FakeSigningKey(_FakeJWKClientByKid.keys_by_kid[kid])


@pytest.fixture()
def es256_supabase_config(app):
    """Pin ES256 Supabase JWT configuration on the test app."""
    app.config["SUPABASE_URL"] = SUPABASE_URL
    app.config["SUPABASE_JWKS_URL"] = ""
    app.config["SUPABASE_JWT_ISSUER"] = ""
    app.config["SUPABASE_JWT_ALGORITHM"] = "ES256"
    app.config["SUPABASE_JWT_AUDIENCE"] = AUDIENCE
    return app


@pytest.fixture()
def es256_verifier(app, monkeypatch, es256_signing_keys, es256_supabase_config):
    """Patch the JWKS client with an EC P-256 key and return it for signing."""
    _, public_pem = es256_signing_keys
    _FakeJWKClient.public_key = public_pem
    monkeypatch.setattr(security_utils, "PyJWKClient", _FakeJWKClient)
    return es256_signing_keys[0]


@pytest.fixture()
def es256_protected_client(app, client, monkeypatch, es256_signing_keys, es256_supabase_config):
    """Client with a ``@require_auth`` protected route verified with ES256."""
    _, public_pem = es256_signing_keys
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

    app.add_url_rule("/api/_tests/protected", "test_protected_es256", protected_view)
    return client, es256_signing_keys[0]


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


class TestDecodeSupabaseTokenES256:
    def test_valid_es256_token_returns_claims(self, app, es256_verifier):
        subject = str(uuid.uuid4())
        claims = security_utils.decode_supabase_token(
            _make_token(es256_verifier, algorithm="ES256", sub=subject)
        )
        assert claims["sub"] == subject
        assert claims["iss"] == f"{SUPABASE_URL}/auth/v1"
        assert claims["aud"] == AUDIENCE
        assert "exp" in claims
        assert claims["role"] == "authenticated"

    def test_expired_es256_token_rejected(self, app, es256_verifier):
        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token(
                _make_token(es256_verifier, algorithm="ES256", expire_in_seconds=-10)
            )

    def test_wrong_audience_rejected(self, app, es256_verifier):
        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token(
                _make_token(es256_verifier, algorithm="ES256", audience="service_role")
            )

    def test_wrong_issuer_rejected(self, app, es256_verifier):
        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token(
                _make_token(
                    es256_verifier,
                    algorithm="ES256",
                    issuer="https://evil.example.com/auth/v1",
                )
            )

    def test_missing_sub_rejected(self, app, es256_verifier):
        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token(
                _make_token(es256_verifier, algorithm="ES256", sub=None)
            )

    def test_non_uuid_sub_rejected(self, app, es256_verifier):
        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token(
                _make_token(es256_verifier, algorithm="ES256", sub="not-a-uuid")
            )

    def test_missing_exp_rejected(self, app, es256_verifier):
        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token(
                _make_token(es256_verifier, algorithm="ES256", exp=None)
            )

    def test_clock_skew_iat_accepted_with_leeway(self, app, es256_verifier):
        future_iat = datetime.now(timezone.utc) + timedelta(seconds=5)
        claims = security_utils.decode_supabase_token(
            _make_token(es256_verifier, algorithm="ES256", iat=future_iat)
        )
        assert claims["sub"]

    def test_clock_skew_iat_rejected_without_leeway(self, app, es256_verifier):
        app.config["SUPABASE_JWT_LEEWAY"] = 0
        future_iat = datetime.now(timezone.utc) + timedelta(seconds=5)
        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token(
                _make_token(es256_verifier, algorithm="ES256", iat=future_iat)
            )

    def test_bad_es256_signature_rejected(self, app, es256_verifier):
        other_private = ec.generate_private_key(ec.SECP256R1())
        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token(
                _make_token(other_private, algorithm="ES256")
            )

    def test_rs256_token_rejected_when_only_es256_configured(self, app, es256_verifier, signing_keys):
        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token(
                _make_token(signing_keys[0], algorithm="RS256")
            )

    def test_garbage_token_rejected(self, app, es256_verifier):
        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token("not.a.jwt")


class TestDecodeSupabaseTokenKidSelection:
    def test_jwks_key_selected_by_kid(self, app, monkeypatch, signing_keys, es256_signing_keys):
        """Both algorithms verify when the JWKS key is matched by ``kid``."""
        rsa_private, rsa_public = signing_keys
        ec_private, ec_public = es256_signing_keys
        _FakeJWKClientByKid.keys_by_kid = {
            "rsa-key": rsa_public,
            "ec-key": ec_public,
        }
        app.config["SUPABASE_JWT_ALGORITHM"] = "ES256,RS256"
        monkeypatch.setattr(security_utils, "PyJWKClient", _FakeJWKClientByKid)

        subject = str(uuid.uuid4())
        claims = security_utils.decode_supabase_token(
            _make_token(ec_private, algorithm="ES256", kid="ec-key", sub=subject)
        )
        assert claims["sub"] == subject

        claims = security_utils.decode_supabase_token(
            _make_token(rsa_private, algorithm="RS256", kid="rsa-key", sub=subject)
        )
        assert claims["sub"] == subject

    def test_wrong_key_for_algorithm_rejected(self, app, monkeypatch, signing_keys, es256_signing_keys):
        """A token verified against the wrong kid-matching key is rejected."""
        rsa_private, rsa_public = signing_keys
        ec_private, _ = es256_signing_keys
        _FakeJWKClientByKid.keys_by_kid = {"rsa-key": rsa_public}
        app.config["SUPABASE_JWT_ALGORITHM"] = "ES256"
        monkeypatch.setattr(security_utils, "PyJWKClient", _FakeJWKClientByKid)

        with pytest.raises(UnauthorizedError):
            security_utils.decode_supabase_token(
                _make_token(ec_private, algorithm="ES256", kid="rsa-key")
            )


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


class TestRequireAuthMiddlewareES256:
    def test_valid_es256_token_authorized(self, es256_protected_client):
        client, private_key = es256_protected_client
        subject = str(uuid.uuid4())
        token = _make_token(private_key, algorithm="ES256", sub=subject)
        response = client.get(
            "/api/_tests/protected",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        body = response.get_json()
        assert body["success"] is True
        assert body["data"]["user_id"] == subject
        assert body["data"]["sub"] == subject

    def test_expired_es256_token_returns_401(self, es256_protected_client):
        client, private_key = es256_protected_client
        token = _make_token(private_key, algorithm="ES256", expire_in_seconds=-10)
        response = client.get(
            "/api/_tests/protected",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 401

    def test_forged_es256_signature_returns_401(self, es256_protected_client):
        client, _ = es256_protected_client
        other_private = ec.generate_private_key(ec.SECP256R1())
        forged = _make_token(other_private, algorithm="ES256")
        response = client.get(
            "/api/_tests/protected",
            headers={"Authorization": f"Bearer {forged}"},
        )
        assert response.status_code == 401

    def test_rs256_token_rejected_by_es256_route(self, es256_protected_client, signing_keys):
        client, _ = es256_protected_client
        token = _make_token(signing_keys[0], algorithm="RS256")
        response = client.get(
            "/api/_tests/protected",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 401
