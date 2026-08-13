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

from flask import has_request_context, request

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


def get_current_access_token() -> str:
    """Return the verified Bearer access token for the current request.

    ``require_auth`` stores the verified token on ``request.access_token``.
    Outside a request context (or when no token was attached) an empty string
    is returned, so user-scoped services degrade gracefully to an anonymous
    client.
    """
    if not has_request_context():
        return ""
    return getattr(request, "access_token", "") or ""


def require_auth(f):
    """Require a valid Supabase Auth JWT.

    Stores the verified claims on ``request.auth`` and the raw access token on
    ``request.access_token`` so downstream services can forward the token to
    user-scoped (RLS-preserving) database operations.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = get_bearer_token()
        claims = decode_supabase_token(token)
        request.auth = claims
        request.access_token = token
        return f(*args, **kwargs)

    return decorated_function
