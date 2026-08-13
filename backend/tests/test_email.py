"""Tests for the phishing email detector (deterministic placeholder)."""

import pytest

from app.errors import ServiceUnavailableError
from app.services.email_service import EmailService


class TestEmailService:
    def test_benign_email(self):
        result = EmailService.analyze_email(
            "Hi Sarah, here is the quarterly report. Let me know if you have questions. Regards, Tom"
        )
        assert result["risk_level"] in {"safe", "suspicious"}
        assert result["is_phishing"] is False

    def test_phishing_email_high_risk(self):
        content = (
            "Dear user, your account has been suspended. Click here immediately to "
            "verify your password and banking details before your account is closed. "
            "Visit http://verify-account.tk now!!"
        )
        result = EmailService.analyze_email(content)
        assert result["risk_level"] == "phishing"
        assert result["is_phishing"] is True
        assert result["risk_score"] >= 70
        names = {i["name"] for i in result["indicators"]}
        assert "Urgency language" in names
        assert "Credential request" in names
        assert "Suspicious link domains" in names

    def test_analyzer_marked_as_placeholder(self):
        result = EmailService.analyze_email("hello")
        assert result["analyzer"] == "deterministic-heuristic-placeholder"

    def test_contract_shape_stable(self):
        result = EmailService.analyze_email("just a normal message")
        for key in ("is_phishing", "risk_level", "risk_score", "confidence", "indicators", "stats", "summary", "analyzer"):
            assert key in result

    def test_non_string_rejected(self):
        with pytest.raises(Exception) as exc:
            EmailService.analyze_email(123)
        assert exc.value.status_code == 400


class TestEmailEndpoint:
    def test_analyze_endpoint(self, client, auth_headers):
        response = client.post(
            "/api/email/analyze",
            json={"content": "click here urgently and verify your password"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.get_json()["data"]["is_phishing"] is True

    def test_missing_content(self, client, auth_headers):
        response = client.post("/api/email/analyze", json={}, headers=auth_headers)
        assert response.status_code == 400

    def test_empty_content(self, client, auth_headers):
        response = client.post("/api/email/analyze", json={"content": ""}, headers=auth_headers)
        assert response.status_code == 400

    def test_content_too_long(self, client, auth_headers):
        response = client.post(
            "/api/email/analyze", json={"content": "a" * 2000}, headers=auth_headers
        )
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"

    @pytest.mark.parametrize("payload", [None, "string", 42])
    def test_invalid_payload(self, client, auth_headers, payload):
        response = client.post("/api/email/analyze", json=payload, headers=auth_headers)
        assert response.status_code == 400


class TestEmailPersistence:
    USER_ID = "22222222-2222-4222-8222-222222222222"

    def test_persists_completed_scan(self, monkeypatch, fake_supabase):
        content = (
            "Subject: Account Update\n"
            "From: security@bank.com\n\n"
            "Dear user, your account has been suspended. Click here immediately to "
            "verify your password. Visit http://verify-account.tk now!!"
        )
        result = EmailService.analyze_email(content, user_id=self.USER_ID)
        assert result["is_phishing"] is True
        payload = fake_supabase.inserts["email_scans"][-1]
        assert payload["user_id"] == self.USER_ID
        assert payload["subject"] == "Account Update"
        assert payload["sender_email"] == "security@bank.com"
        assert payload["predicted_label"] == "phishing"
        assert payload["confidence"] == result["confidence"]
        assert payload["risk_level"] == "phishing"
        assert payload["indicators"] == result["indicators"]
        assert payload["model_version"] == "deterministic-heuristic-placeholder"
        assert set(payload) == {
            "user_id", "subject", "sender_email", "predicted_label",
            "confidence", "risk_level", "indicators", "model_version",
        }

    def test_persists_safe_email(self, monkeypatch, fake_supabase):
        content = (
            "Subject: Quarterly Report\n"
            "From: colleague@company.com\n\n"
            "Hi Sarah, here is the quarterly report. Let me know if you have questions."
        )
        result = EmailService.analyze_email(content, user_id=self.USER_ID)
        assert result["is_phishing"] is False
        payload = fake_supabase.inserts["email_scans"][-1]
        assert payload["predicted_label"] == "safe"
        assert payload["risk_level"] in {"safe", "suspicious"}

    def test_skips_persistence_without_user(self, fake_supabase):
        content = "click here urgently and verify your password"
        result = EmailService.analyze_email(content)
        assert result["is_phishing"] is True
        assert "email_scans" not in fake_supabase.inserts

    def test_skips_persistence_when_client_unconfigured(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.email_service.get_user_supabase_client", lambda access_token=None: None
        )
        content = "click here urgently and verify your password"
        result = EmailService.analyze_email(content, user_id=self.USER_ID)
        assert result["is_phishing"] is True

    def test_database_failure_raises_service_unavailable(self, fake_supabase, monkeypatch):
        fake_supabase.fail_next_execute = True
        content = "click here urgently and verify your password"
        with pytest.raises(ServiceUnavailableError):
            EmailService.analyze_email(content, user_id=self.USER_ID)


class TestEmailPersistenceEndpoint:
    def test_analyze_endpoint_persists_scan(self, client, auth_headers, fake_supabase, auth_user_id):
        content = (
            "Subject: Security Alert\n"
            "From: alerts@security.com\n\n"
            "Dear user, your account has been suspended. Click here immediately to "
            "verify your password and banking details before your account is closed. "
            "Visit http://verify-account.tk now!!"
        )
        response = client.post(
            "/api/email/analyze", json={"content": content}, headers=auth_headers
        )
        assert response.status_code == 200
        body = response.get_json()
        assert body["success"] is True
        assert body["data"]["is_phishing"] is True
        payload = fake_supabase.inserts["email_scans"][-1]
        assert payload["subject"] == "Security Alert"
        assert payload["sender_email"] == "alerts@security.com"
        assert payload["predicted_label"] == "phishing"
        assert payload["user_id"] == auth_user_id

    def test_analyze_endpoint_ignores_user_id_from_body(
        self, client, auth_headers, auth_user_id, fake_supabase
    ):
        content = (
            "Subject: Test\n"
            "From: test@test.com\n\n"
            "Dear user, your account has been suspended. Click here immediately to "
            "verify your password and banking details. Visit http://verify-account.tk now!!"
        )
        response = client.post(
            "/api/email/analyze",
            json={"content": content, "user_id": "99999999-9999-4999-8999-999999999999"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        payload = fake_supabase.inserts["email_scans"][-1]
        assert payload["user_id"] == auth_user_id

    def test_analyze_endpoint_database_failure_returns_503(
        self, client, auth_headers, fake_supabase
    ):
        fake_supabase.fail_next_execute = True
        content = (
            "Subject: Test\n"
            "From: test@test.com\n\n"
            "Dear user, your account has been suspended. Click here immediately to "
            "verify your password. Visit http://verify-account.tk now!!"
        )
        response = client.post(
            "/api/email/analyze", json={"content": content}, headers=auth_headers
        )
        assert response.status_code == 503
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "SERVICE_UNAVAILABLE"
