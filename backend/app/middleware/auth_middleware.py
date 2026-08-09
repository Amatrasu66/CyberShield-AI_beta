"""
JWT authentication middleware.

Decorators protecting API endpoints. Token verification reuses the JWT helpers
in ``app/utils/security.py``; because authentication persistence is pending the
Supabase integration, this decorator is available but not yet attached to any
route.
"""

from functools import wraps

from flask import request

from ..errors import UnauthorizedError
from ..utils.security import decode_token


def get_bearer_token() -> str:
    """Extract and validate the Bearer token from the Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise UnauthorizedError("Missing bearer token")
    return auth[len("Bearer "):].strip()


def require_auth(f):
    """Require a valid JWT access token. Stores claims on ``request.auth``."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = get_bearer_token()
        claims = decode_token(token)
        request.auth = claims
        return f(*args, **kwargs)

    return decorated_function
