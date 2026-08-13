"""Tests for the Supabase Auth integration (JWT-verified profile lookup).

Supabase Auth owns registration/login; the Flask side only resolves the
authenticated user's profile from ``public.profiles`` using the verified JWT
``sub`` claim. No password is ever accepted, stored or hashed here.
"""

import uuid

import pytest

from app.services.auth_service import AuthService

USER_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def _profile_row(user_id, **overrides):
    row = {
        "id": user_id,
        "full_name": "Ada Lovelace",
        "role": "Faculty",
        "created_at": "2026-08-13T10:00:00+00:00",
        "updated_at": None,
    }
    row.update(overrides)
    return row


class TestAuthService:
    def test_get_profile_returns_row_when_present(self, fake_supabase):
        fake_supabase.seed("profiles", [_profile_row(USER_ID)])
        profile = AuthService.get_profile(USER_ID)
        assert profile["id"] == USER_ID
        assert profile["full_name"] == "Ada Lovelace"
        assert profile["role"] == "Faculty"

    def test_get_profile_returns_none_when_missing(self, fake_supabase):
        assert AuthService.get_profile(USER_ID) is None

    def test_get_profile_without_user_id_returns_none(self, fake_supabase):
        assert AuthService.get_profile("") is None

    def test_get_profile_ignores_other_users_rows(self, fake_supabase):
        other = str(uuid.uuid4())
        fake_supabase.seed("profiles", [_profile_row(other, full_name="Someone Else")])
        assert AuthService.get_profile(USER_ID) is None

    def test_get_profile_runs_with_request_access_token(self, fake_supabase):
        fake_supabase.seed("profiles", [_profile_row(USER_ID)])
        AuthService.get_profile(USER_ID)
        assert fake_supabase.auth_tokens == [""]

    def test_get_profile_db_failure_is_service_unavailable(self, fake_supabase):
        fake_supabase.fail_next_execute = True
        with pytest.raises(Exception) as exc:
            AuthService.get_profile(USER_ID)
        assert exc.value.status_code == 503
        assert exc.value.code == "SERVICE_UNAVAILABLE"


class TestAuthEndpoints:
    def test_me_authenticated_returns_profile(self, client, auth_headers, auth_user_id, fake_supabase):
        fake_supabase.seed("profiles", [_profile_row(auth_user_id)])
        response = client.get("/api/auth/me", headers=auth_headers)
        assert response.status_code == 200
        body = response.get_json()
        assert body["success"] is True
        assert body["data"]["id"] == auth_user_id
        assert body["data"]["full_name"] == "Ada Lovelace"
        assert body["data"]["role"] == "Faculty"

    def test_me_authenticated_without_profile_returns_identity(self, client, auth_headers, auth_user_id):
        response = client.get("/api/auth/me", headers=auth_headers)
        assert response.status_code == 200
        body = response.get_json()
        assert body["success"] is True
        assert body["data"]["id"] == auth_user_id

    def test_me_unauthenticated_returns_401(self, client):
        response = client.get("/api/auth/me")
        assert response.status_code == 401
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "UNAUTHORIZED"
        assert "data" not in body

    def test_me_invalid_token_returns_401(self, client):
        response = client.get("/api/auth/me", headers={"Authorization": "Bearer not.a.jwt"})
        assert response.status_code == 401
        assert response.get_json()["error"]["code"] == "UNAUTHORIZED"

    def test_me_uses_verified_jwt_user_id_not_body(self, client, auth_headers, auth_user_id, fake_supabase):
        fake_supabase.seed("profiles", [_profile_row(auth_user_id)])
        response = client.get(
            "/api/auth/me",
            json={"user_id": "99999999-9999-4999-8999-999999999999"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.get_json()["data"]["id"] == auth_user_id

    def test_me_is_read_only(self, client, auth_headers):
        response = client.get("/api/auth/me", headers=auth_headers)
        assert response.status_code == 200
        assert response.get_json()["success"] is True
