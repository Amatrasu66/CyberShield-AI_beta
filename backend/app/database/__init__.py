"""
Database package.

Exposes the Supabase client factories used by the service layer:
a low-privilege client (publishable key) and an elevated server-only
client (secret key).
"""

from .supabase_client import get_supabase_admin_client, get_supabase_client

__all__ = ["get_supabase_admin_client", "get_supabase_client"]
