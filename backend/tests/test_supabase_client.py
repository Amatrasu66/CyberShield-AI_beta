"""Tests for the Supabase client factory."""

import pytest
from supabase import Client

from app.config import settings
from app.database import get_supabase_admin_client, get_supabase_client

CONFIG_KEYS = (
    "SUPABASE_URL",
    "SUPABASE_PUBLISHABLE_KEY",
    "SUPABASE_SECRET_KEY",
    "SUPABASE_ANON_KEY",
    "SUPABASE_SERVICE_ROLE_KEY",
    "SUPABASE_KEY",
)


@pytest.fixture()
def clean_client_cache():
    """Ensure the client factory caches do not leak between tests."""
    get_supabase_client.cache_clear()
    get_supabase_admin_client.cache_clear()
    yield
    get_supabase_client.cache_clear()
    get_supabase_admin_client.cache_clear()


def test_unconfigured_returns_none(monkeypatch, clean_client_cache):
    for name in CONFIG_KEYS:
        monkeypatch.setattr(settings.Config, name, "")
    assert get_supabase_client() is None
    assert get_supabase_admin_client() is None


def test_configured_publishable_returns_client(monkeypatch, clean_client_cache):
    monkeypatch.setattr(settings.Config, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(settings.Config, "SUPABASE_PUBLISHABLE_KEY", "sb_publishable_test")
    client = get_supabase_client()
    assert isinstance(client, Client)


def test_configured_secret_returns_admin_client(monkeypatch, clean_client_cache):
    monkeypatch.setattr(settings.Config, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(settings.Config, "SUPABASE_SECRET_KEY", "sb_secret_test")
    client = get_supabase_admin_client()
    assert isinstance(client, Client)


def test_client_is_cached(monkeypatch, clean_client_cache):
    monkeypatch.setattr(settings.Config, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(settings.Config, "SUPABASE_PUBLISHABLE_KEY", "sb_publishable_test")
    assert get_supabase_client() is get_supabase_client()


def test_admin_client_is_cached(monkeypatch, clean_client_cache):
    monkeypatch.setattr(settings.Config, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(settings.Config, "SUPABASE_SECRET_KEY", "sb_secret_test")
    assert get_supabase_admin_client() is get_supabase_admin_client()


def test_publishable_key_preferred_over_legacy_anon(monkeypatch, clean_client_cache):
    monkeypatch.setattr(settings.Config, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(settings.Config, "SUPABASE_PUBLISHABLE_KEY", "sb_publishable_test")
    monkeypatch.setattr(settings.Config, "SUPABASE_ANON_KEY", "legacy-anon-key")
    monkeypatch.setattr(settings.Config, "SUPABASE_KEY", "legacy-key")
    assert isinstance(get_supabase_client(), Client)


def test_legacy_anon_key_fallback(monkeypatch, clean_client_cache):
    monkeypatch.setattr(settings.Config, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(settings.Config, "SUPABASE_PUBLISHABLE_KEY", "")
    monkeypatch.setattr(settings.Config, "SUPABASE_ANON_KEY", "legacy-anon-key")
    monkeypatch.setattr(settings.Config, "SUPABASE_KEY", "legacy-key")
    assert isinstance(get_supabase_client(), Client)


def test_legacy_key_fallback(monkeypatch, clean_client_cache):
    monkeypatch.setattr(settings.Config, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(settings.Config, "SUPABASE_PUBLISHABLE_KEY", "")
    monkeypatch.setattr(settings.Config, "SUPABASE_ANON_KEY", "")
    monkeypatch.setattr(settings.Config, "SUPABASE_KEY", "legacy-key")
    assert isinstance(get_supabase_client(), Client)


def test_secret_key_preferred_over_legacy_service_role(monkeypatch, clean_client_cache):
    monkeypatch.setattr(settings.Config, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(settings.Config, "SUPABASE_SECRET_KEY", "sb_secret_test")
    monkeypatch.setattr(settings.Config, "SUPABASE_SERVICE_ROLE_KEY", "legacy-service-role-key")
    assert isinstance(get_supabase_admin_client(), Client)


def test_legacy_service_role_key_fallback(monkeypatch, clean_client_cache):
    monkeypatch.setattr(settings.Config, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(settings.Config, "SUPABASE_SECRET_KEY", "")
    monkeypatch.setattr(settings.Config, "SUPABASE_SERVICE_ROLE_KEY", "legacy-service-role-key")
    assert isinstance(get_supabase_admin_client(), Client)


def test_missing_key_returns_none(monkeypatch, clean_client_cache):
    monkeypatch.setattr(settings.Config, "SUPABASE_URL", "https://example.supabase.co")
    for name in (
        "SUPABASE_PUBLISHABLE_KEY",
        "SUPABASE_ANON_KEY",
        "SUPABASE_KEY",
        "SUPABASE_SECRET_KEY",
        "SUPABASE_SERVICE_ROLE_KEY",
    ):
        monkeypatch.setattr(settings.Config, name, "")
    assert get_supabase_client() is None
    assert get_supabase_admin_client() is None
