"""
Database package.

Exposes the Supabase client factory used by the service layer.
"""

from .supabase_client import get_supabase_client

__all__ = ["get_supabase_client"]
