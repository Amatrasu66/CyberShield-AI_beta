"""Tests for URL validation and the website scanner."""

import pytest

from app.errors import ServiceUnavailableError, ValidationError
from app.services.scanner_service import ScannerService
from app.utils.validators import is_private_host, validate_url


def _fetch_ok(**overrides):
    base = {
        "error": None,
        "error_message": None,
        "final_url": "https://example.com/home",
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
        "raw_set_cookie": ["session=abc123; Secure; HttpOnly; SameSite=Lax; Path=/"],
        "cert": {"notAfter": "20270101000000Z"},
        "size_warning": None,
    }
    base.update(overrides)
    return base


SCAN_CONFIG = {
    "SCANNER_ALLOW_PRIVATE_ADDRESSES": True,
    "SCANNER_MAX_REDIRECTS": 5,
    "SCANNER_TIMEOUT": 10,
    "SCANNER_MAX_RESPONSE_SIZE": 512000,
    "SCANNER_USER_AGENT": "CyberShieldAI-Test/1.0",
}


class TestValidateUrl:
    @pytest.mark.parametrize("url", [
        "https://example.com",
        "http://example.com/path?q=1",
        "https://sub.example.org:8443/x",
    ])
    def test_valid_urls(self, url):
        assert validate_url(url) == url

    @pytest.mark.parametrize("url", [
        "ftp://example.com",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "not-a-url",
        "https://",
        "https://user:pass@example.com",
        "https://example.com:99999",
        "",
    ])
    def test_invalid_urls(self, url):
        with pytest.raises(ValidationError):
            validate_url(url)

    def test_url_too_long(self):
        with pytest.raises(ValidationError):
            validate_url("https://example.com/" + "a" * 3000, max_length=100)

    def test_non_string_url(self):
        with pytest.raises(ValidationError):
            validate_url(12345)


class TestScannerService:
    def test_secure_site_scores_high(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.scanner_service.ScannerService._fetch",
            staticmethod(lambda url, cfg: _fetch_ok()),
        )
        result = ScannerService.scan_website("https://example.com", SCAN_CONFIG)
        assert result["reachable"] is True
        assert result["score"] >= 90
        assert result["grade"] in {"A", "B"}

    def test_insecure_site_scores_low(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.scanner_service.ScannerService._fetch",
            staticmethod(lambda url, cfg: _fetch_ok(
                final_url="http://example.com",
                final_scheme="http",
                status_code=200,
                headers={"server": "nginx/1.24.0", "x-powered-by": "PHP/8.1"},
                raw_set_cookie=["sid=abc; Path=/"],
                cert=None,
            )),
        )
        result = ScannerService.scan_website("http://example.com", SCAN_CONFIG)
        assert result["reachable"] is True
        assert result["score"] <= 30
        names = [c["name"] for c in result["checks"]]
        assert "HTTPS enforcement" in names
        assert "TLS certificate" in names
        assert "Information disclosure" in names

    def test_unreachable_target(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.scanner_service.ScannerService._fetch",
            staticmethod(lambda url, cfg: {
                "error": "connection",
                "error_message": "Could not connect to the target server.",
                "final_url": url,
                "final_scheme": "https",
                "status_code": None,
                "headers": {},
                "raw_set_cookie": [],
                "cert": None,
            }),
        )
        result = ScannerService.scan_website("https://down.example.com", SCAN_CONFIG)
        assert result["reachable"] is False
        assert result["error"] == "connection"
        assert result["score"] == 0
        assert result["grade"] == "F"

    def test_private_host_refused(self, app, monkeypatch):
        app.config["SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        monkeypatch.setattr(
            "app.services.scanner_service.is_private_host", lambda url: True
        )
        with pytest.raises(ValidationError):
            ScannerService.scan_website("http://192.168.1.10")

    def test_cookie_warning_when_insecure(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.scanner_service.ScannerService._fetch",
            staticmethod(lambda url, cfg: _fetch_ok(
                raw_set_cookie=["sid=abc; Path=/"],
            )),
        )
        result = ScannerService.scan_website("https://example.com", SCAN_CONFIG)
        cookie_check = next(c for c in result["checks"] if c["name"] == "Cookie security")
        assert cookie_check["status"] == "warning"

    def test_cors_wildcard_warns(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.scanner_service.ScannerService._fetch",
            staticmethod(lambda url, cfg: _fetch_ok(
                headers={** _fetch_ok()["headers"], "access-control-allow-origin": "*"},
            )),
        )
        result = ScannerService.scan_website("https://example.com", SCAN_CONFIG)
        cors_check = next(c for c in result["checks"] if c["name"] == "CORS policy")
        assert cors_check["status"] == "warning"

    def test_scan_result_has_stable_shape(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.scanner_service.ScannerService._fetch",
            staticmethod(lambda url, cfg: _fetch_ok()),
        )
        result = ScannerService.scan_website("https://example.com", SCAN_CONFIG)
        for key in ("target", "reachable", "score", "grade", "checks", "scan_duration_ms", "summary"):
            assert key in result


class TestScannerEndpoint:
    def test_scan_endpoint_returns_result(self, client, monkeypatch, auth_headers):
        monkeypatch.setattr(
            "app.services.scanner_service.ScannerService._fetch",
            staticmethod(lambda url, cfg: _fetch_ok()),
        )
        response = client.post(
            "/api/scanner/website", json={"url": "https://example.com"}, headers=auth_headers
        )
        assert response.status_code == 200
        body = response.get_json()
        assert body["success"] is True
        assert body["data"]["reachable"] is True

    def test_scan_endpoint_invalid_url(self, client, monkeypatch, auth_headers):
        monkeypatch.setattr(
            "app.services.scanner_service.ScannerService._fetch",
            staticmethod(lambda url, cfg: _fetch_ok()),
        )
        response = client.post(
            "/api/scanner/website", json={"url": "ftp://example.com"}, headers=auth_headers
        )
        assert response.status_code == 400

    def test_scan_endpoint_missing_url(self, client, auth_headers):
        response = client.post("/api/scanner/website", json={}, headers=auth_headers)
        assert response.status_code == 400


class TestScannerPersistence:
    USER_ID = "11111111-1111-4111-8111-111111111111"

    def test_persists_completed_scan(self, fake_supabase, monkeypatch):
        monkeypatch.setattr(
            "app.services.scanner_service.ScannerService._fetch",
            staticmethod(lambda url, cfg: _fetch_ok()),
        )
        result = ScannerService.scan_website(
            "https://example.com", SCAN_CONFIG, user_id=self.USER_ID
        )
        assert result["reachable"] is True
        payload = fake_supabase.inserts["website_scans"][-1]
        assert payload["user_id"] == self.USER_ID
        assert payload["target_url"] == "https://example.com"
        assert payload["status"] == "completed"
        assert payload["security_score"] == result["score"]
        assert payload["risk_level"] in {"low", "medium", "high", "critical"}
        assert payload["findings"] == result["checks"]
        assert set(payload) == {
            "user_id", "target_url", "status", "security_score", "risk_level", "findings",
        }

    def test_skips_persistence_without_user(self, fake_supabase, monkeypatch):
        monkeypatch.setattr(
            "app.services.scanner_service.ScannerService._fetch",
            staticmethod(lambda url, cfg: _fetch_ok()),
        )
        result = ScannerService.scan_website("https://example.com", SCAN_CONFIG)
        assert result["reachable"] is True
        assert "website_scans" not in fake_supabase.inserts

    def test_skips_persistence_when_client_unconfigured(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.scanner_service.ScannerService._fetch",
            staticmethod(lambda url, cfg: _fetch_ok()),
        )
        monkeypatch.setattr(
            "app.services.scanner_service.get_user_supabase_client", lambda access_token=None: None
        )
        result = ScannerService.scan_website(
            "https://example.com", SCAN_CONFIG, user_id=self.USER_ID
        )
        assert result["reachable"] is True

    def test_skips_persistence_for_unreachable_scan(self, fake_supabase, monkeypatch):
        monkeypatch.setattr(
            "app.services.scanner_service.ScannerService._fetch",
            staticmethod(lambda url, cfg: {
                "error": "connection",
                "error_message": "Could not connect to the target server.",
                "final_url": url,
                "final_scheme": "https",
                "status_code": None,
                "headers": {},
                "raw_set_cookie": [],
                "cert": None,
            }),
        )
        result = ScannerService.scan_website(
            "https://down.example.com", SCAN_CONFIG, user_id=self.USER_ID
        )
        assert result["reachable"] is False
        assert "website_scans" not in fake_supabase.inserts

    def test_database_failure_raises_service_unavailable(self, fake_supabase, monkeypatch):
        fake_supabase.fail_next_execute = True
        monkeypatch.setattr(
            "app.services.scanner_service.ScannerService._fetch",
            staticmethod(lambda url, cfg: _fetch_ok()),
        )
        with pytest.raises(ServiceUnavailableError):
            ScannerService.scan_website(
                "https://example.com", SCAN_CONFIG, user_id=self.USER_ID
            )


class TestScannerPersistenceEndpoint:
    def test_scan_endpoint_persists_scan(self, client, monkeypatch, auth_headers, fake_supabase):
        monkeypatch.setattr(
            "app.services.scanner_service.ScannerService._fetch",
            staticmethod(lambda url, cfg: _fetch_ok()),
        )
        response = client.post(
            "/api/scanner/website", json={"url": "https://example.com"}, headers=auth_headers
        )
        assert response.status_code == 200
        body = response.get_json()
        assert body["success"] is True
        assert body["data"]["reachable"] is True
        payload = fake_supabase.inserts["website_scans"][-1]
        assert payload["target_url"] == "https://example.com"
        assert payload["status"] == "completed"

    def test_scan_endpoint_ignores_user_id_from_body(
        self, client, monkeypatch, auth_headers, auth_user_id, fake_supabase
    ):
        monkeypatch.setattr(
            "app.services.scanner_service.ScannerService._fetch",
            staticmethod(lambda url, cfg: _fetch_ok()),
        )
        response = client.post(
            "/api/scanner/website",
            json={"url": "https://example.com", "user_id": "99999999-9999-4999-8999-999999999999"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        payload = fake_supabase.inserts["website_scans"][-1]
        assert payload["user_id"] == auth_user_id

    def test_scan_endpoint_database_failure_returns_503(
        self, client, monkeypatch, auth_headers, fake_supabase
    ):
        fake_supabase.fail_next_execute = True
        monkeypatch.setattr(
            "app.services.scanner_service.ScannerService._fetch",
            staticmethod(lambda url, cfg: _fetch_ok()),
        )
        response = client.post(
            "/api/scanner/website", json={"url": "https://example.com"}, headers=auth_headers
        )
        assert response.status_code == 503
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "SERVICE_UNAVAILABLE"
