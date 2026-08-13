"""Auth enforcement tests for the protected API routes."""

import uuid

import pytest

from app.reports.storage import ReportStorageService


@pytest.fixture(autouse=True)
def _fake_report_storage(monkeypatch):
    """Replace report storage I/O so report endpoints run without Supabase Storage."""
    def fake_upload(pdf_file, user_id, report_id, config=None):
        return {
            "storage_path": f"{user_id}/{report_id}.pdf",
            "signed_url": f"https://storage.example/{user_id}/{report_id}.pdf?token=abc",
        }

    def fake_signed_url(user_id, report_id, config=None):
        return f"https://storage.example/{user_id}/{report_id}.pdf?token=abc"

    monkeypatch.setattr(ReportStorageService, "upload_pdf", staticmethod(fake_upload))
    monkeypatch.setattr(ReportStorageService, "get_signed_url", staticmethod(fake_signed_url))


def _assert_unauthorized(response):
    assert response.status_code == 401
    body = response.get_json()
    assert body["success"] is False
    assert body["error"]["code"] == "UNAUTHORIZED"
    assert body["message"]
    assert "data" not in body


class TestProtectedRoutesRequireAuth:
    @pytest.mark.parametrize("method,path,json", [
        ("get", "/api/auth/me", None),
        ("post", "/api/scanner/website", {"url": "https://example.com"}),
        ("post", "/api/email/analyze", {"content": "hello"}),
        ("post", "/api/password/analyze", {"password": "CorrectHorseBatteryStaple!9"}),
        ("post", "/api/logs/analyze", {"content": "GET / HTTP/1.1 200"}),
        ("get", "/api/reports", None),
        ("post", "/api/reports/generate", {"title": "Audit"}),
    ])
    def test_missing_token_returns_401(self, client, method, path, json):
        response = getattr(client, method)(path, json=json)
        _assert_unauthorized(response)

    @pytest.mark.parametrize("method,path,json", [
        ("post", "/api/email/analyze", {"content": "hello"}),
        ("get", "/api/reports", None),
    ])
    def test_invalid_token_returns_401(self, client, method, path, json):
        response = getattr(client, method)(
            path, json=json, headers={"Authorization": "Bearer not.a.jwt"}
        )
        _assert_unauthorized(response)

    def test_auth_check_runs_before_validation(self, client):
        response = client.post("/api/email/analyze", json={})
        _assert_unauthorized(response)


class TestProtectedRoutesAuthenticated:
    def test_scanner_endpoint_authenticated(self, client, auth_headers, monkeypatch):
        monkeypatch.setattr(
            "app.services.scanner_service.ScannerService._fetch",
            staticmethod(lambda url, cfg: {
                "error": None,
                "error_message": None,
                "final_url": url,
                "final_scheme": "https",
                "status_code": 200,
                "headers": {
                    "content-security-policy": "default-src 'self'",
                    "strict-transport-security": "max-age=31536000",
                    "x-content-type-options": "nosniff",
                    "x-frame-options": "DENY",
                    "referrer-policy": "no-referrer",
                    "permissions-policy": "camera=()",
                },
                "raw_set_cookie": [],
                "cert": {"notAfter": "20270101000000Z"},
            }),
        )
        response = client.post(
            "/api/scanner/website", json={"url": "https://example.com"}, headers=auth_headers
        )
        assert response.status_code == 200
        assert response.get_json()["data"]["reachable"] is True

    def test_email_endpoint_authenticated(self, client, auth_headers):
        response = client.post(
            "/api/email/analyze",
            json={"content": "click here and verify your password"},
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_password_endpoint_authenticated(self, client, auth_headers):
        response = client.post(
            "/api/password/analyze",
            json={"password": "Tr0ub4dor&3xample!Secure"},
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_logs_endpoint_authenticated(self, client, auth_headers):
        log_line = '1.1.1.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        response = client.post(
            "/api/logs/analyze", json={"content": log_line}, headers=auth_headers
        )
        assert response.status_code == 200

    def test_reports_generate_and_list_authenticated(self, client, auth_headers):
        created = client.post(
            "/api/reports/generate", json={"title": "My audit"}, headers=auth_headers
        )
        assert created.status_code == 201
        listed = client.get("/api/reports", headers=auth_headers)
        assert listed.status_code == 200
        assert listed.get_json()["meta"]["count"] == 1


class TestUserScoping:
    def test_reports_scoped_to_authenticated_user(self, client, make_auth_token):
        user_a = str(uuid.uuid4())
        user_b = str(uuid.uuid4())
        headers_a = {"Authorization": f"Bearer {make_auth_token(user_a)}"}
        headers_b = {"Authorization": f"Bearer {make_auth_token(user_b)}"}

        client.post("/api/reports/generate", json={"title": "A's report"}, headers=headers_a)
        client.post("/api/reports/generate", json={"title": "A's second"}, headers=headers_a)
        client.post("/api/reports/generate", json={"title": "B's report"}, headers=headers_b)

        own = client.get("/api/reports", headers=headers_a).get_json()
        assert own["meta"]["count"] == 2
        assert all(r["title"].startswith("A's") for r in own["data"])

        other = client.get("/api/reports", headers=headers_b).get_json()
        assert other["meta"]["count"] == 1
        assert other["data"][0]["title"] == "B's report"

    def test_client_supplied_user_id_is_ignored(self, client, make_auth_token):
        sub = str(uuid.uuid4())
        headers = {"Authorization": f"Bearer {make_auth_token(sub)}"}
        response = client.post(
            "/api/reports/generate",
            json={"title": "Trust check", "user_id": "attacker-controlled-id"},
            headers=headers,
        )
        assert response.status_code == 201
        assert response.get_json()["data"]["user_id"] == sub


class TestPublicEndpoints:
    def test_health_and_version_do_not_require_auth(self, client):
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/version").status_code == 200
