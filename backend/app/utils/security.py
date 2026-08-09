"""
Security & hashing helpers.

Implements password hashing (bcrypt) and JWT token helpers used by the
authentication layer. These utilities are dependency-free of any database so
they are fully usable and testable in the current phase.

Never log passwords or sensitive credentials.
"""

import datetime
import uuid

import bcrypt
import jwt

from flask import current_app

from ..errors import UnauthorizedError

BCRYPT_ROUNDS = 12


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
