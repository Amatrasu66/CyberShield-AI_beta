"""
Supabase PostgreSQL client factory.

Builds a lazily initialized, process-wide Supabase client from the application
configuration. No network traffic occurs at import time; the client is created
on first use and cached for the lifetime of the process.
"""

from functools import lru_cache

from supabase import Client, create_client

from ..config import get_config


@lru_cache(maxsize=1)
def get_supabase_client() -> Client | None:
    """Return the shared Supabase client, or ``None`` when not configured.

    The service-role key is preferred for trusted server-side operations and
    falls back to the anon key. Missing configuration returns ``None`` instead
    of raising, so the app still starts during local development.

    Returns:
        A configured :class:`supabase.Client`, or ``None`` if ``SUPABASE_URL``
        and a key are not both present.
    """
    cfg = get_config()
    url = (cfg.SUPABASE_URL or "").strip()
    key = (
        cfg.SUPABASE_SERVICE_ROLE_KEY
        or cfg.SUPABASE_ANON_KEY
        or cfg.SUPABASE_KEY
    )
    key = (key or "").strip()
    if not url or not key:
        return None
    return create_client(url, key)
