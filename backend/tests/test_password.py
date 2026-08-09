"""Tests for the password analyzer service and endpoint."""

import pytest

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
    def test_analyze_password_endpoint(self, client):
        response = client.post("/api/password/analyze", json={"password": "CorrectHorseBatteryStaple!9"})
        assert response.status_code == 200
        body = response.get_json()
        assert body["success"] is True
        data = body["data"]
        assert "strength" in data
        assert "entropy_bits" in data
        assert "recommendations" in data

    def test_missing_password(self, client):
        response = client.post("/api/password/analyze", json={})
        assert response.status_code == 400
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "VALIDATION_ERROR"

    def test_password_too_long(self, client):
        response = client.post("/api/password/analyze", json={"password": "x" * 100})
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"

    def test_non_string_password(self, client):
        response = client.post("/api/password/analyze", json={"password": 12345})
        assert response.status_code == 400

    @pytest.mark.parametrize("payload", [
        None,
        "not a dict",
        {"password": None},
    ])
    def test_invalid_payloads(self, client, payload):
        response = client.post("/api/password/analyze", json=payload)
        assert response.status_code == 400
