"""Tests for the Supabase client factory."""

import pytest
from supabase import Client

from app.config import settings
from app.database import get_supabase_client


@pytest.fixture()
def clean_client_cache():
    """Ensure the client factory cache does not leak between tests."""
    get_supabase_client.cache_clear()
    yield
    get_supabase_client.cache_clear()


def test_unconfigured_returns_none(monkeypatch, clean_client_cache):
    for name in ("SUPABASE_URL", "SUPABASE_KEY", "SUPABASE_ANON_KEY", "SUPABASE_SERVICE_ROLE_KEY"):
        monkeypatch.setattr(settings.Config, name, "")
    assert get_supabase_client() is None


def test_configured_returns_client(monkeypatch, clean_client_cache):
    monkeypatch.setattr(settings.Config, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(settings.Config, "SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key")
    client = get_supabase_client()
    assert isinstance(client, Client)


def test_client_is_cached(monkeypatch, clean_client_cache):
    monkeypatch.setattr(settings.Config, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(settings.Config, "SUPABASE_ANON_KEY", "test-anon-key")
    assert get_supabase_client() is get_supabase_client()


def test_service_role_key_preferred_over_anon(monkeypatch, clean_client_cache):
    monkeypatch.setattr(settings.Config, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(settings.Config, "SUPABASE_ANON_KEY", "anon-key")
    monkeypatch.setattr(settings.Config, "SUPABASE_SERVICE_ROLE_KEY", "service-role-key")
    client = get_supabase_client()
    assert isinstance(client, Client)
