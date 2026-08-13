"""Integration-safe tests for RLS-preserving, user-scoped database operations.

These exercise the full authenticated request path -- Flask verifies the
Supabase JWT in the middleware, then the service layer forwards that same access
token to the user-scoped Supabase client. Tests prove that:

- every scan persistence and report read/write runs with the request's access
  token (``fake_supabase.auth_tokens``),
- the persisted ``user_id`` always equals the verified JWT ``sub``
  (``auth.uid()`` in RLS), never the request body.

No network is involved: the Supabase client is the in-memory fake from
``conftest`` and report storage I/O is mocked.
"""

import uuid

import pytest

from app.middleware import get_current_access_token
from app.reports.storage import ReportStorageService
from app.services.email_service import EmailService
from app.services.scanner_service import ScannerService

USER_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


@pytest.fixture()
def report_storage(monkeypatch):
    """Replace report storage I/O with a deterministic in-memory fake."""
    def fake_upload(pdf_file, user_id, report_id, config=None):
        return {
            "storage_path": f"{user_id}/{report_id}.pdf",
            "signed_url": f"https://storage.example/{user_id}/{report_id}.pdf?token=abc",
        }

    def fake_signed_url(user_id, report_id, config=None):
        return f"https://storage.example/{user_id}/{report_id}.pdf?token=abc"

    monkeypatch.setattr(ReportStorageService, "upload_pdf", staticmethod(fake_upload))
    monkeypatch.setattr(ReportStorageService, "get_signed_url", staticmethod(fake_signed_url))


def _fetch_ok(url, cfg):
    return {
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
    }


class TestAccessTokenHelper:
    def test_empty_outside_request_context(self):
        assert get_current_access_token() == ""


class TestScanPersistenceRunsAsUser:
    def test_website_scan_forwards_token_and_scopes_to_auth_uid(
        self, client, auth_headers, auth_token, auth_user_id, fake_supabase, monkeypatch
    ):
        monkeypatch.setattr(
            "app.services.scanner_service.ScannerService._fetch", staticmethod(_fetch_ok)
        )
        response = client.post(
            "/api/scanner/website", json={"url": "https://example.com"}, headers=auth_headers
        )
        assert response.status_code == 200
        assert fake_supabase.auth_tokens == [auth_token]
        payload = fake_supabase.inserts["website_scans"][-1]
        assert payload["user_id"] == auth_user_id

    def test_email_scan_forwards_token_and_scopes_to_auth_uid(
        self, client, auth_headers, auth_token, auth_user_id, fake_supabase
    ):
        response = client.post(
            "/api/email/analyze",
            json={"content": "click here immediately and verify your password"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert fake_supabase.auth_tokens == [auth_token]
        assert fake_supabase.inserts["email_scans"][-1]["user_id"] == auth_user_id

    def test_password_scan_forwards_token_and_scopes_to_auth_uid(
        self, client, auth_headers, auth_token, auth_user_id, fake_supabase
    ):
        response = client.post(
            "/api/password/analyze",
            json={"password": "Tr0ub4dor&3xample!Secure"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert fake_supabase.auth_tokens == [auth_token]
        assert fake_supabase.inserts["password_scans"][-1]["user_id"] == auth_user_id

    def test_log_scan_forwards_token_and_scopes_to_auth_uid(
        self, client, auth_headers, auth_token, auth_user_id, fake_supabase
    ):
        log_line = '1.1.1.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        response = client.post(
            "/api/logs/analyze", json={"content": log_line}, headers=auth_headers
        )
        assert response.status_code == 200
        assert fake_supabase.auth_tokens == [auth_token]
        assert fake_supabase.inserts["log_scans"][-1]["user_id"] == auth_user_id


class TestReportOperationsRunAsUser:
    def test_generate_and_list_forward_token_and_scope_to_auth_uid(
        self, client, auth_headers, auth_token, auth_user_id, fake_supabase, report_storage
    ):
        generated = client.post(
            "/api/reports/generate", json={"title": "Audit"}, headers=auth_headers
        )
        assert generated.status_code == 201
        assert fake_supabase.auth_tokens[-1] == auth_token
        assert fake_supabase.inserts["reports"][-1]["user_id"] == auth_user_id

        listed = client.get("/api/reports", headers=auth_headers)
        assert listed.status_code == 200
        assert fake_supabase.auth_tokens[-1] == auth_token

    def test_generate_scan_reads_run_with_user_token(
        self, client, auth_headers, auth_token, auth_user_id, fake_supabase, report_storage
    ):
        fake_supabase.seed("website_scans", [{
            "id": "w-1",
            "user_id": auth_user_id,
            "target_url": "https://example.com",
            "status": "completed",
            "security_score": 80,
            "risk_level": "low",
            "findings": [],
            "created_at": "2026-08-13T10:00:00+00:00",
        }])
        response = client.post(
            "/api/reports/generate", json={"title": "Audit"}, headers=auth_headers
        )
        assert response.status_code == 201
        assert fake_supabase.auth_tokens == [auth_token]
        assert response.get_json()["data"]["report_data"]["website_scan"]["score"] == 80


class TestUserScopingAcrossRequests:
    def test_tokens_and_rows_are_isolated_per_user(
        self, client, make_auth_token, fake_supabase
    ):
        user_a = str(uuid.uuid4())
        user_b = str(uuid.uuid4())
        token_a = make_auth_token(user_a)
        token_b = make_auth_token(user_b)

        client.post(
            "/api/email/analyze",
            json={"content": "hello, nothing suspicious here"},
            headers={"Authorization": f"Bearer {token_a}"},
        )
        client.post(
            "/api/email/analyze",
            json={"content": "click here and verify your account immediately"},
            headers={"Authorization": f"Bearer {token_b}"},
        )

        assert fake_supabase.auth_tokens == [token_a, token_b]
        rows = fake_supabase.inserts["email_scans"]
        assert rows[0]["user_id"] == user_a
        assert rows[1]["user_id"] == user_b

    def test_user_id_in_body_is_never_trusted(
        self, client, auth_headers, auth_token, auth_user_id, fake_supabase, monkeypatch
    ):
        monkeypatch.setattr(
            "app.services.scanner_service.ScannerService._fetch", staticmethod(_fetch_ok)
        )
        response = client.post(
            "/api/scanner/website",
            json={
                "url": "https://example.com",
                "user_id": "99999999-9999-4999-8999-999999999999",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert fake_supabase.auth_tokens == [auth_token]
        assert fake_supabase.inserts["website_scans"][-1]["user_id"] == auth_user_id


class TestDirectServiceCallsWithoutRequestContext:
    def test_direct_service_call_does_not_need_http_request(self, fake_supabase):
        result = EmailService.analyze_email("just a normal message", user_id=USER_ID)
        assert result["is_phishing"] is False
        assert fake_supabase.auth_tokens == [""]
        assert fake_supabase.inserts["email_scans"][-1]["user_id"] == USER_ID
