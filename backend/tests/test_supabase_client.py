"""Tests for the Supabase client factory."""

import pytest
from supabase import Client

from app.config import settings
from app.database import (
    get_supabase_admin_client,
    get_supabase_client,
    get_user_supabase_client,
)

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


def _configure_user_client(monkeypatch):
    """Configure valid low-privilege credentials for user-scoped tests."""
    monkeypatch.setattr(settings.Config, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(settings.Config, "SUPABASE_PUBLISHABLE_KEY", "sb_publishable_test")
    monkeypatch.setattr(settings.Config, "SUPABASE_ANON_KEY", "")
    monkeypatch.setattr(settings.Config, "SUPABASE_KEY", "")
    monkeypatch.setattr(settings.Config, "SUPABASE_SECRET_KEY", "")
    monkeypatch.setattr(settings.Config, "SUPABASE_SERVICE_ROLE_KEY", "")


class TestUserSupabaseClient:
    """The user-scoped client must receive the user's access token."""

    def test_forwards_access_token_as_bearer(self, monkeypatch):
        _configure_user_client(monkeypatch)
        client = get_user_supabase_client("user.jwt.access.token")
        assert isinstance(client, Client)
        assert client.postgrest.headers.get("authorization") == "Bearer user.jwt.access.token"

    def test_forwards_user_token_not_publishable_key(self, monkeypatch):
        _configure_user_client(monkeypatch)
        client = get_user_supabase_client("user.jwt.access.token")
        auth_header = client.postgrest.headers.get("authorization")
        assert auth_header == "Bearer user.jwt.access.token"
        assert "sb_publishable_test" not in auth_header

    def test_uses_publishable_key_not_secret(self, monkeypatch):
        _configure_user_client(monkeypatch)
        monkeypatch.setattr(settings.Config, "SUPABASE_SECRET_KEY", "sb_secret_test")
        client = get_user_supabase_client("token")
        assert client.postgrest.headers.get("apikey") == "sb_publishable_test"

    def test_no_token_authenticates_as_anon_role(self, monkeypatch):
        """Without a user token the client authenticates with the publishable key
        (anon role), never with a different user's identity."""
        _configure_user_client(monkeypatch)
        client = get_user_supabase_client(None)
        assert client.postgrest.headers.get("authorization") == "Bearer sb_publishable_test"

    def test_empty_token_authenticates_as_anon_role(self, monkeypatch):
        _configure_user_client(monkeypatch)
        client = get_user_supabase_client("")
        assert client.postgrest.headers.get("authorization") == "Bearer sb_publishable_test"

    def test_unconfigured_returns_none(self, monkeypatch):
        for name in ("SUPABASE_URL", "SUPABASE_PUBLISHABLE_KEY", "SUPABASE_ANON_KEY", "SUPABASE_KEY"):
            monkeypatch.setattr(settings.Config, name, "")
        assert get_user_supabase_client("token") is None

    def test_missing_low_privilege_key_returns_none(self, monkeypatch):
        monkeypatch.setattr(settings.Config, "SUPABASE_URL", "https://example.supabase.co")
        monkeypatch.setattr(settings.Config, "SUPABASE_PUBLISHABLE_KEY", "")
        monkeypatch.setattr(settings.Config, "SUPABASE_ANON_KEY", "")
        monkeypatch.setattr(settings.Config, "SUPABASE_KEY", "")
        monkeypatch.setattr(settings.Config, "SUPABASE_SECRET_KEY", "sb_secret_test")
        assert get_user_supabase_client("token") is None

    def test_fresh_client_per_request_prevents_token_races(self, monkeypatch):
        """Per-request tokens must never race on a shared client instance."""
        _configure_user_client(monkeypatch)
        client_a = get_user_supabase_client("token-a")
        client_b = get_user_supabase_client("token-b")
        assert client_a is not client_b
        assert client_a.postgrest.headers.get("authorization") == "Bearer token-a"
        assert client_b.postgrest.headers.get("authorization") == "Bearer token-b"
