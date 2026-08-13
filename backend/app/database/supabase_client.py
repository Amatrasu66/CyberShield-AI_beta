"""
Supabase PostgreSQL client factory.

Builds lazily initialized, process-wide Supabase clients from the application
configuration. No network traffic occurs at import time; clients are created
on first use and cached for the lifetime of the process.

Three client profiles are exposed:

- :func:`get_supabase_client`: cached, low-privilege client backed by the
  publishable key. It runs as the ``anon``/``authenticated`` Postgres roles, so
  Row Level Security is preserved. Because it is shared process-wide it must
  never be impersonated with a per-request token.
- :func:`get_user_supabase_client`: a fresh, per-request low-privilege client
  authenticated as the requesting user. It uses the publishable key and
  forwards the user's verified access token, so PostgREST evaluates Row Level
  Security as ``auth.uid()``. This is the client to use for all user-scoped
  database operations.
- :func:`get_supabase_admin_client`: elevated client backed by the secret key.
  It runs as the ``service_role`` Postgres role and bypasses Row Level
  Security. Server-only; never expose it to the frontend.
"""

from functools import lru_cache

from supabase import Client, create_client

from ..config import get_config


def _first_key(*values: str) -> str:
    """Return the first non-empty, stripped value."""
    for value in values:
        stripped = (value or "").strip()
        if stripped:
            return stripped
    return ""


def _publishable_key() -> str:
    """Resolve the low-privilege publishable key (with legacy fallbacks)."""
    cfg = get_config()
    return _first_key(
        cfg.SUPABASE_PUBLISHABLE_KEY,
        cfg.SUPABASE_ANON_KEY,
        cfg.SUPABASE_KEY,
    )


def _build_client(url: str, key: str) -> Client | None:
    """Build a Supabase client, or ``None`` when either input is missing.

    Missing configuration returns ``None`` instead of raising, so the app
    still starts during local development.
    """
    url = (url or "").strip()
    key = (key or "").strip()
    if not url or not key:
        return None
    return create_client(url, key)


@lru_cache(maxsize=1)
def get_supabase_client() -> Client | None:
    """Return the shared low-privilege Supabase client, or ``None``.

    Uses the publishable key, falling back to the legacy anon key and then the
    legacy ``SUPABASE_KEY`` for backward compatibility. Access is constrained
    by Row Level Security.

    Returns:
        A configured :class:`supabase.Client`, or ``None`` if ``SUPABASE_URL``
        and a low-privilege key are not both present.
    """
    cfg = get_config()
    return _build_client(cfg.SUPABASE_URL, _publishable_key())


def get_user_supabase_client(access_token: str = None) -> Client | None:
    """Return a low-privilege client authenticated as the requesting user.

    A fresh client is created for each call (never cached) so per-request
    access tokens cannot race across threads on a shared session. The client
    uses the publishable key and, when ``access_token`` is supplied, forwards
    it as the Bearer token so PostgREST runs as that user and Row Level
    Security is preserved. Normal user-scoped reads/writes must go through this
    client; the secret/admin client must not be used for them.

    Args:
        access_token: the user's verified Supabase Auth access token (from the
            Flask request). When empty, the client stays anonymous.

    Returns:
        A configured :class:`supabase.Client`, or ``None`` if ``SUPABASE_URL``
        and a low-privilege key are not both present.
    """
    cfg = get_config()
    client = _build_client(cfg.SUPABASE_URL, _publishable_key())
    if client is None:
        return None
    if access_token:
        client.postgrest.auth(access_token)
    return client


@lru_cache(maxsize=1)
def get_supabase_admin_client() -> Client | None:
    """Return the shared elevated Supabase client, or ``None``.

    Uses the secret key, falling back to the legacy service-role key for
    backward compatibility. The client runs with elevated privileges that
    bypass Row Level Security; use it only for trusted server-side operations
    and never expose it to the frontend.

    Returns:
        A configured :class:`supabase.Client`, or ``None`` if ``SUPABASE_URL``
        and an elevated key are not both present.
    """
    cfg = get_config()
    key = _first_key(
        cfg.SUPABASE_SECRET_KEY,
        cfg.SUPABASE_SERVICE_ROLE_KEY,
    )
    return _build_client(cfg.SUPABASE_URL, key)
