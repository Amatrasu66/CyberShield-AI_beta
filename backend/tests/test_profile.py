"""Profile update tests — Phase 3A-2.

Covers PATCH /api/auth/me security invariants:

- authenticated user sees own profile (isolated)
- full name persists via RLS-scoped update
- empty / invalid names rejected
- role cannot be self-escalated
- user_id cannot be supplied to access or overwrite another profile
- unauthenticated access remains 401
- JWT forwarding preserved (per-request user client)
"""

import uuid

import pytest

from app.services.auth_service import AuthService


def _profile_row(user_id, **overrides):
    row = {
        "id": user_id,
        "full_name": "Original Name",
        "role": "Student",
        "created_at": "2026-08-10T10:00:00+00:00",
        "updated_at": None,
    }
    row.update(overrides)
    return row


class TestProfileUpdateService:
    def test_update_persists_and_returns_row(self, fake_supabase):
        user_id = str(uuid.uuid4())
        fake_supabase.seed("profiles", [_profile_row(user_id)])
        updated = AuthService.update_profile(user_id, "Ada Lovelace")
        assert updated["full_name"] == "Ada Lovelace"
        assert updated["id"] == user_id
        # re-read proves persistence within fake DB
        assert AuthService.get_profile(user_id)["full_name"] == "Ada Lovelace"

    def test_update_trims_whitespace(self, fake_supabase):
        user_id = str(uuid.uuid4())
        fake_supabase.seed("profiles", [_profile_row(user_id)])
        updated = AuthService.update_profile(user_id, "  Ada  ")
        assert updated["full_name"] == "Ada"

    def test_update_rejects_empty(self, fake_supabase):
        user_id = str(uuid.uuid4())
        fake_supabase.seed("profiles", [_profile_row(user_id)])
        with pytest.raises(Exception) as exc:
            AuthService.update_profile(user_id, "   ")
        assert exc.value.status_code == 400

    def test_update_rejects_too_long(self, fake_supabase):
        user_id = str(uuid.uuid4())
        fake_supabase.seed("profiles", [_profile_row(user_id)])
        with pytest.raises(Exception) as exc:
            AuthService.update_profile(user_id, "A" * 101)
        assert exc.value.status_code == 400

    def test_update_rejects_control_chars(self, fake_supabase):
        user_id = str(uuid.uuid4())
        fake_supabase.seed("profiles", [_profile_row(user_id)])
        with pytest.raises(Exception) as exc:
            AuthService.update_profile(user_id, "Ada\x00Lovelace")
        assert exc.value.status_code == 400


class TestProfileEndpoints:
    def test_patch_authenticated_updates_full_name(self, client, auth_headers, auth_user_id, fake_supabase):
        fake_supabase.seed("profiles", [_profile_row(auth_user_id)])
        resp = client.patch("/api/auth/me", json={"full_name": "Ada Lovelace"}, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()["data"]["full_name"] == "Ada Lovelace"
        assert resp.get_json()["data"]["id"] == auth_user_id
        # GET reflects saved value
        get = client.get("/api/auth/me", headers=auth_headers)
        assert get.get_json()["data"]["full_name"] == "Ada Lovelace"

    def test_put_alias_also_works(self, client, auth_headers, auth_user_id, fake_supabase):
        fake_supabase.seed("profiles", [_profile_row(auth_user_id)])
        resp = client.put("/api/auth/me", json={"full_name": "Grace Hopper"}, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()["data"]["full_name"] == "Grace Hopper"

    def test_profile_isolation_between_users(self, client, make_auth_token, fake_supabase):
        user_a = str(uuid.uuid4())
        user_b = str(uuid.uuid4())
        fake_supabase.seed("profiles", [_profile_row(user_a, full_name="Alice"), _profile_row(user_b, full_name="Bob")])
        headers_a = {"Authorization": f"Bearer {make_auth_token(user_a)}"}
        headers_b = {"Authorization": f"Bearer {make_auth_token(user_b)}"}

        # A updates only own row
        client.patch("/api/auth/me", json={"full_name": "Alice Updated"}, headers=headers_a)
        assert client.get("/api/auth/me", headers=headers_a).get_json()["data"]["full_name"] == "Alice Updated"
        assert client.get("/api/auth/me", headers=headers_b).get_json()["data"]["full_name"] == "Bob"

        # B's update does not leak into A
        client.patch("/api/auth/me", json={"full_name": "Bob Updated"}, headers=headers_b)
        assert client.get("/api/auth/me", headers=headers_a).get_json()["data"]["full_name"] == "Alice Updated"

    def test_empty_name_rejected(self, client, auth_headers, auth_user_id, fake_supabase):
        fake_supabase.seed("profiles", [_profile_row(auth_user_id)])
        resp = client.patch("/api/auth/me", json={"full_name": "   "}, headers=auth_headers)
        assert resp.status_code == 400
        assert resp.get_json()["error"]["code"] == "VALIDATION_ERROR"

    def test_too_long_name_rejected(self, client, auth_headers, auth_user_id, fake_supabase):
        fake_supabase.seed("profiles", [_profile_row(auth_user_id)])
        resp = client.patch("/api/auth/me", json={"full_name": "A" * 101}, headers=auth_headers)
        assert resp.status_code == 400

    def test_missing_full_name_rejected(self, client, auth_headers, auth_user_id, fake_supabase):
        fake_supabase.seed("profiles", [_profile_row(auth_user_id)])
        resp = client.patch("/api/auth/me", json={}, headers=auth_headers)
        assert resp.status_code == 400

    def test_non_string_full_name_rejected(self, client, auth_headers, auth_user_id, fake_supabase):
        fake_supabase.seed("profiles", [_profile_row(auth_user_id)])
        resp = client.patch("/api/auth/me", json={"full_name": 123}, headers=auth_headers)
        assert resp.status_code == 400

    def test_role_escalation_rejected(self, client, auth_headers, auth_user_id, fake_supabase):
        fake_supabase.seed("profiles", [_profile_row(auth_user_id, role="Student")])
        resp = client.patch("/api/auth/me", json={"full_name": "Alice", "role": "Faculty"}, headers=auth_headers)
        assert resp.status_code == 400
        assert "role" in resp.get_json()["message"].lower() or "not allowed" in resp.get_json()["message"].lower()
        # Role unchanged
        assert client.get("/api/auth/me", headers=auth_headers).get_json()["data"]["role"] == "Student"

    def test_role_only_payload_rejected(self, client, auth_headers, auth_user_id, fake_supabase):
        fake_supabase.seed("profiles", [_profile_row(auth_user_id)])
        resp = client.patch("/api/auth/me", json={"role": "Internship Evaluator"}, headers=auth_headers)
        assert resp.status_code == 400

    def test_email_field_rejected(self, client, auth_headers, auth_user_id, fake_supabase):
        fake_supabase.seed("profiles", [_profile_row(auth_user_id)])
        resp = client.patch("/api/auth/me", json={"full_name": "Alice", "email": "attacker@evil.com"}, headers=auth_headers)
        assert resp.status_code == 400

    def test_user_id_in_body_is_ignored_rejected(self, client, auth_headers, auth_user_id, make_auth_token, fake_supabase):
        other = str(uuid.uuid4())
        fake_supabase.seed("profiles", [_profile_row(auth_user_id, full_name="Alice"), _profile_row(other, full_name="Bob")])
        resp = client.patch("/api/auth/me", json={"full_name": "Hacked", "user_id": other}, headers=auth_headers)
        assert resp.status_code == 400
        # No cross-user write occurred
        assert client.get("/api/auth/me", headers=auth_headers).get_json()["data"]["full_name"] == "Alice"
        headers_other = {"Authorization": f"Bearer {make_auth_token(other)}"}
        assert client.get("/api/auth/me", headers=headers_other).get_json()["data"]["full_name"] == "Bob"

    def test_id_field_rejected(self, client, auth_headers, auth_user_id, fake_supabase):
        fake_supabase.seed("profiles", [_profile_row(auth_user_id)])
        resp = client.patch("/api/auth/me", json={"full_name": "Alice", "id": str(uuid.uuid4())}, headers=auth_headers)
        assert resp.status_code == 400

    def test_unauthenticated_patch_returns_401(self, client):
        resp = client.patch("/api/auth/me", json={"full_name": "Alice"})
        assert resp.status_code == 401
        assert resp.get_json()["error"]["code"] == "UNAUTHORIZED"

    def test_invalid_token_patch_returns_401(self, client):
        resp = client.patch("/api/auth/me", json={"full_name": "Alice"}, headers={"Authorization": "Bearer not.a.jwt"})
        assert resp.status_code == 401

    def test_jwt_forwarded_to_user_client(self, client, auth_headers, auth_user_id, fake_supabase, auth_token):
        fake_supabase.seed("profiles", [_profile_row(auth_user_id)])
        fake_supabase.auth_tokens.clear()
        client.patch("/api/auth/me", json={"full_name": "Forwarded"}, headers=auth_headers)
        # service used get_user_supabase_client(access_token) — token should have been recorded
        assert auth_token in fake_supabase.auth_tokens

    def test_non_json_body_rejected(self, client, auth_headers, auth_user_id, fake_supabase):
        fake_supabase.seed("profiles", [_profile_row(auth_user_id)])
        resp = client.patch("/api/auth/me", data="not json", content_type="application/json", headers=auth_headers)
        assert resp.status_code == 400
