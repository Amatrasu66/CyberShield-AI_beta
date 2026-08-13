"""
Supabase JWT authentication middleware.

Decorators protecting API endpoints. Bearer tokens are verified against the
Supabase Auth signing keys (see ``app/utils/security.py``), which validates
signature, issuer, audience, expiry and subject claims and returns the user UUID
from the ``sub`` claim. Verified claims are stored on ``request.auth`` for the
protected handler.

Attach to a route with ``@require_auth`` to protect it; unauthenticated
requests receive HTTP 401.
"""

from functools import wraps

from flask import request

from ..errors import UnauthorizedError
from ..utils.security import decode_supabase_token


def get_bearer_token() -> str:
    """Extract and validate the Bearer token from the Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise UnauthorizedError("Missing bearer token")
    return auth[len("Bearer "):].strip()


def get_current_user_id() -> str:
    """Return the authenticated user UUID (``sub`` claim) for the request.

    Only valid inside a request handled by :func:`require_auth`; raises
    :class:`UnauthorizedError` otherwise.
    """
    claims = getattr(request, "auth", None)
    if not claims or not claims.get("sub"):
        raise UnauthorizedError("Authentication required")
    return claims["sub"]


def require_auth(f):
    """Require a valid Supabase Auth JWT. Stores claims on ``request.auth``."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = get_bearer_token()
        claims = decode_supabase_token(token)
        request.auth = claims
        return f(*args, **kwargs)

    return decorated_function
