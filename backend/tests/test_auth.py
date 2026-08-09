"""Tests for authentication scaffolding (validated but deferred to Supabase)."""

import pytest

from app.services.auth_service import AuthService


class TestAuthService:
    def test_register_returns_feature_unavailable(self):
        with pytest.raises(Exception) as exc:
            AuthService.register("user@example.com", "StrongPass123!")
        assert exc.value.status_code == 501
        assert exc.value.code == "AUTH_UNAVAILABLE"

    def test_login_returns_feature_unavailable(self):
        with pytest.raises(Exception) as exc:
            AuthService.login("user@example.com", "StrongPass123!")
        assert exc.value.status_code == 501
        assert exc.value.code == "AUTH_UNAVAILABLE"

    def test_invalid_email_rejected(self):
        with pytest.raises(Exception) as exc:
            AuthService.register("not-an-email", "StrongPass123!")
        assert exc.value.status_code == 400

    def test_short_password_rejected(self):
        with pytest.raises(Exception) as exc:
            AuthService.register("user@example.com", "short")
        assert exc.value.status_code == 400

    def test_missing_password_rejected(self):
        with pytest.raises(Exception) as exc:
            AuthService.login("user@example.com", "")
        assert exc.value.status_code == 400


class TestAuthEndpoints:
    def test_register_endpoint_501(self, client):
        response = client.post("/api/auth/register", json={"email": "a@b.com", "password": "StrongPass123!"})
        assert response.status_code == 501
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "AUTH_UNAVAILABLE"
        assert "Supabase" in body["message"]

    def test_login_endpoint_501(self, client):
        response = client.post("/api/auth/login", json={"email": "a@b.com", "password": "StrongPass123!"})
        assert response.status_code == 501

    def test_register_invalid_input(self, client):
        response = client.post("/api/auth/register", json={"email": "nope", "password": "x"})
        assert response.status_code == 400

    def test_register_missing_fields(self, client):
        response = client.post("/api/auth/register", json={})
        assert response.status_code == 400
