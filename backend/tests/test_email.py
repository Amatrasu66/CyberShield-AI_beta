"""Tests for the phishing email detector (deterministic placeholder)."""

import pytest

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
    def test_analyze_endpoint(self, client):
        response = client.post("/api/email/analyze", json={"content": "click here urgently and verify your password"})
        assert response.status_code == 200
        assert response.get_json()["data"]["is_phishing"] is True

    def test_missing_content(self, client):
        response = client.post("/api/email/analyze", json={})
        assert response.status_code == 400

    def test_empty_content(self, client):
        response = client.post("/api/email/analyze", json={"content": ""})
        assert response.status_code == 400

    def test_content_too_long(self, client):
        response = client.post("/api/email/analyze", json={"content": "a" * 2000})
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"

    @pytest.mark.parametrize("payload", [None, "string", 42])
    def test_invalid_payload(self, client, payload):
        response = client.post("/api/email/analyze", json=payload)
        assert response.status_code == 400
