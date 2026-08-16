"""
Security & hashing helpers.

Implements password hashing (bcrypt) and JWT token helpers used by the
authentication layer. These utilities are dependency-free of any database so
they are fully usable and testable in the current phase.

Never log passwords or sensitive credentials.
"""

import datetime
import logging
import uuid

import bcrypt
import jwt
from jwt import PyJWKClient

from flask import current_app

from ..errors import UnauthorizedError

BCRYPT_ROUNDS = 12

logger = logging.getLogger("cybershield.auth")


def hash_password(password: str) -> str:
    """Hash a plaintext password with bcrypt (never store plaintext)."""
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def _jwt_secret() -> str:
    return current_app.config.get("SECRET_KEY", "dev-insecure-secret-key-change-me")


def create_access_token(subject: str, extra_claims: dict = None) -> str:
    """Create a signed JWT access token for ``subject``."""
    now = datetime.datetime.now(datetime.timezone.utc)
    claims = {
        "sub": subject,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + datetime.timedelta(
            minutes=int(current_app.config.get("JWT_EXPIRATION_MINUTES", 60))
        ),
    }
    if extra_claims:
        claims.update(extra_claims)
    return jwt.encode(
        claims, _jwt_secret(), algorithm=current_app.config.get("JWT_ALGORITHM", "HS256")
    )


def decode_token(token: str) -> dict:
    """Decode and verify a JWT token. Raises :class:`UnauthorizedError` on failure."""
    try:
        return jwt.decode(
            token,
            _jwt_secret(),
            algorithms=[current_app.config.get("JWT_ALGORITHM", "HS256")],
        )
    except jwt.PyJWTError:
        raise UnauthorizedError("Invalid or expired token")


def _supabase_jwks_url() -> str:
    """Resolve the Supabase project JWKS endpoint from configuration."""
    explicit = current_app.config.get("SUPABASE_JWKS_URL", "")
    if explicit:
        return explicit
    base = (current_app.config.get("SUPABASE_URL", "") or "").rstrip("/")
    return f"{base}/auth/v1/.well-known/jwks.json" if base else ""


def _supabase_issuer() -> str:
    """Resolve the expected Supabase token issuer from configuration."""
    explicit = current_app.config.get("SUPABASE_JWT_ISSUER", "")
    if explicit:
        return explicit
    base = (current_app.config.get("SUPABASE_URL", "") or "").rstrip("/")
    return f"{base}/auth/v1" if base else ""


def _supabase_algorithms() -> list:
    """Resolve the allowed Supabase JWT signing algorithms.

    ``SUPABASE_JWT_ALGORITHM`` may name a single algorithm (e.g. ``ES256``) or
    a comma-separated list (e.g. ``ES256,RS256``) to accept both while Supabase
    signs access tokens during key rotation.
    """
    configured = current_app.config.get("SUPABASE_JWT_ALGORITHM", "") or "ES256"
    algorithms = [alg.strip() for alg in str(configured).split(",") if alg.strip()]
    return algorithms or ["ES256"]


def _get_jwks_client() -> PyJWKClient:
    """Return the per-app JWKS client, constructed once and cached."""
    app = current_app
    client = app.extensions.get("cybershield_jwks_client")
    if client is None:
        client = PyJWKClient(
            _supabase_jwks_url(),
            cache_keys=True,
            max_cached_keys=10,
        )
        app.extensions["cybershield_jwks_client"] = client
    return client


def decode_supabase_token(token: str) -> dict:
    """Verify a Supabase Auth access token and return its claims.

    Resolves the project signing key from the Supabase JWKS endpoint, matching
    the key by ``kid``, then verifies the token signature (ES256 by default)
    and the ``iss``, ``aud``, ``exp`` and ``sub`` claims. ``sub`` must be the
    user UUID (``auth.uid()`` in Supabase RLS).

    Raises :class:`UnauthorizedError` (HTTP 401) for missing configuration,
    unverifiable signatures, expired tokens, invalid claims, or a subject that
    is not a valid UUID.
    """
    jwks_url = _supabase_jwks_url()
    if not jwks_url:
        raise UnauthorizedError(
            "Supabase JWT verification is not configured",
            details={
                "hint": "Set SUPABASE_URL (or SUPABASE_JWKS_URL) and SUPABASE_JWT_ISSUER"
            },
        )

    algorithms = _supabase_algorithms()
    audience = current_app.config.get("SUPABASE_JWT_AUDIENCE", "authenticated")
    issuer = _supabase_issuer() or None
    leeway = int(current_app.config.get("SUPABASE_JWT_LEEWAY", 10) or 0)

    try:
        signing_key = _get_jwks_client().get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=algorithms,
            audience=audience,
            issuer=issuer,
            leeway=leeway,
            options={"require": ["sub", "exp"]},
        )
    except jwt.PyJWTError as exc:
        logger.warning("Supabase JWT rejected: %s", exc.__class__.__name__)
        raise UnauthorizedError("Invalid or expired token") from exc
    except (OSError, ValueError) as exc:
        logger.warning("Supabase JWKS fetch failed: %s", exc.__class__.__name__)
        raise UnauthorizedError("Unable to verify token signature") from exc

    subject = claims.get("sub")
    try:
        uuid.UUID(str(subject))
    except (ValueError, TypeError, AttributeError):
        logger.warning("Supabase JWT rejected: sub is not a valid UUID")
        raise UnauthorizedError("Invalid or expired token")

    return claims
