"""Tests for the password analyzer service and endpoint."""

import pytest

from app.errors import ServiceUnavailableError
from app.services.password_service import PasswordService


class TestPasswordService:
    def test_weak_short_password(self):
        result = PasswordService.analyze_password("abc")
        assert result["length"] == 3
        assert result["strength"] == "Weak"
        assert result["strength_score"] < 40
        assert result["crack_time_estimate"] == "instantly"
        assert result["recommendations"]

    def test_strong_password(self):
        result = PasswordService.analyze_password("Tr0ub4dor&3xample!Secure")
        assert result["strength"] == "Strong"
        assert result["strength_score"] >= 85
        assert result["classes_used"] == 4
        assert result["entropy_bits"] > 100

    def test_character_class_detection(self):
        result = PasswordService.analyze_password("Abc123!@")
        assert result["uppercase"] is True
        assert result["lowercase"] is True
        assert result["digits"] is True
        assert result["special"] is True
        assert set(result["char_classes"]) == {"uppercase", "lowercase", "digits", "special"}

    def test_common_weak_password_flagged(self):
        result = PasswordService.analyze_password("password")
        assert result["in_common_list"] is True
        assert result["strength"] == "Weak"

    def test_entropy_is_deterministic(self):
        a = PasswordService.analyze_password("CorrectHorseBattery")
        b = PasswordService.analyze_password("CorrectHorseBattery")
        assert a["entropy_bits"] == b["entropy_bits"]
        assert a["strength_score"] == b["strength_score"]

    def test_no_raw_password_in_result(self):
        secret = "S3cr3t!Pa55word"
        result = PasswordService.analyze_password(secret)
        assert secret not in str(result)


class TestPasswordEndpoint:
    def test_analyze_password_endpoint(self, client, auth_headers):
        response = client.post(
            "/api/password/analyze",
            json={"password": "CorrectHorseBatteryStaple!9"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        body = response.get_json()
        assert body["success"] is True
        data = body["data"]
        assert "strength" in data
        assert "entropy_bits" in data
        assert "recommendations" in data

    def test_missing_password(self, client, auth_headers):
        response = client.post("/api/password/analyze", json={}, headers=auth_headers)
        assert response.status_code == 400
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "VALIDATION_ERROR"

    def test_password_too_long(self, client, auth_headers):
        response = client.post(
            "/api/password/analyze", json={"password": "x" * 100}, headers=auth_headers
        )
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"

    def test_non_string_password(self, client, auth_headers):
        response = client.post(
            "/api/password/analyze", json={"password": 12345}, headers=auth_headers
        )
        assert response.status_code == 400

    @pytest.mark.parametrize("payload", [
        None,
        "not a dict",
        {"password": None},
    ])
    def test_invalid_payloads(self, client, auth_headers, payload):
        response = client.post("/api/password/analyze", json=payload, headers=auth_headers)
        assert response.status_code == 400


class TestPasswordPersistence:
    USER_ID = "33333333-3333-4333-8333-333333333333"

    def test_persists_completed_scan(self, fake_supabase):
        result = PasswordService.analyze_password(
            "Tr0ub4dor&3xample!Secure", user_id=self.USER_ID
        )
        payload = fake_supabase.inserts["password_scans"][-1]
        assert payload["user_id"] == self.USER_ID
        assert payload["password_length"] == result["length"]
        assert payload["entropy"] == result["entropy_bits"]
        assert payload["strength_score"] == result["strength_score"]
        assert payload["strength_label"] == result["strength"]
        assert payload["has_upper"] == result["uppercase"]
        assert payload["has_lower"] == result["lowercase"]
        assert payload["has_number"] == result["digits"]
        assert payload["has_symbol"] == result["special"]
        assert payload["breached"] == result["in_common_list"]
        assert set(payload) == {
            "user_id", "password_length", "entropy", "strength_score",
            "strength_label", "has_upper", "has_lower", "has_number",
            "has_symbol", "breached",
        }

    def test_persists_weak_breached_password(self, fake_supabase):
        result = PasswordService.analyze_password("password", user_id=self.USER_ID)
        payload = fake_supabase.inserts["password_scans"][-1]
        assert payload["breached"] is True
        assert payload["strength_label"] == "Weak"

    def test_never_stores_plaintext_password_or_hash(self, fake_supabase):
        secret = "S3cr3t!Pa55word"
        PasswordService.analyze_password(secret, user_id=self.USER_ID)
        payload = fake_supabase.inserts["password_scans"][-1]
        assert secret not in str(payload)
        assert "hash" not in payload
        assert "bcrypt" not in str(payload).lower()

    def test_skips_persistence_without_user(self, fake_supabase):
        result = PasswordService.analyze_password("CorrectHorseBatteryStaple!9")
        assert result["strength_score"] is not None
        assert "password_scans" not in fake_supabase.inserts

    def test_skips_persistence_when_client_unconfigured(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.password_service.get_user_supabase_client", lambda access_token=None: None
        )
        result = PasswordService.analyze_password(
            "CorrectHorseBatteryStaple!9", user_id=self.USER_ID
        )
        assert result["strength_score"] is not None

    def test_database_failure_raises_service_unavailable(self, fake_supabase):
        fake_supabase.fail_next_execute = True
        with pytest.raises(ServiceUnavailableError):
            PasswordService.analyze_password(
                "CorrectHorseBatteryStaple!9", user_id=self.USER_ID
            )

    def test_persistence_preserves_analysis_result(self, fake_supabase):
        password = "CorrectHorseBatteryStaple!9"
        result = PasswordService.analyze_password(password, user_id=self.USER_ID)
        assert result["length"] == len(password)
        assert result["entropy_bits"] > 0
        assert result["strength"] in {"Weak", "Fair", "Good", "Strong"}
        assert "recommendations" in result
        assert result["in_common_list"] is False


class TestPasswordPersistenceEndpoint:
    def test_analyze_endpoint_persists_scan(
        self, client, auth_headers, fake_supabase, auth_user_id
    ):
        response = client.post(
            "/api/password/analyze",
            json={"password": "CorrectHorseBatteryStaple!9"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        payload = fake_supabase.inserts["password_scans"][-1]
        assert payload["user_id"] == auth_user_id
        assert payload["password_length"] == len("CorrectHorseBatteryStaple!9")
        assert payload["has_upper"] is True
        assert payload["has_lower"] is True
        assert payload["has_number"] is True
        assert payload["has_symbol"] is True
        assert payload["breached"] is False
        assert "password" not in payload

    def test_analyze_endpoint_ignores_user_id_from_body(
        self, client, auth_headers, auth_user_id, fake_supabase
    ):
        response = client.post(
            "/api/password/analyze",
            json={
                "password": "CorrectHorseBatteryStaple!9",
                "user_id": "99999999-9999-4999-8999-999999999999",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        payload = fake_supabase.inserts["password_scans"][-1]
        assert payload["user_id"] == auth_user_id

    def test_analyze_endpoint_database_failure_returns_503(
        self, client, auth_headers, fake_supabase
    ):
        fake_supabase.fail_next_execute = True
        response = client.post(
            "/api/password/analyze",
            json={"password": "CorrectHorseBatteryStaple!9"},
            headers=auth_headers,
        )
        assert response.status_code == 503
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "SERVICE_UNAVAILABLE"
