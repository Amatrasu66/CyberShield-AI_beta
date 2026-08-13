"""
Supabase PostgreSQL client factory.

Builds lazily initialized, process-wide Supabase clients from the application
configuration. No network traffic occurs at import time; clients are created
on first use and cached for the lifetime of the process.

Two client profiles are exposed:

- :func:`get_supabase_client`: low-privilege client backed by the publishable
  key. It runs as the ``anon``/``authenticated`` Postgres roles, so Row Level
  Security is preserved. This is the default client for user-scoped access.
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
    key = _first_key(
        cfg.SUPABASE_PUBLISHABLE_KEY,
        cfg.SUPABASE_ANON_KEY,
        cfg.SUPABASE_KEY,
    )
    return _build_client(cfg.SUPABASE_URL, key)


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
