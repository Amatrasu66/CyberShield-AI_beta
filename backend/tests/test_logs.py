"""Tests for the log analyzer service and endpoint."""

import pytest

from app.errors import ServiceUnavailableError
from app.services.log_service import LogService

SAMPLE_LOG = """\
1.2.3.4 - - [01/Jan/2026:10:00:01 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
1.2.3.4 - - [01/Jan/2026:10:00:05 +0000] "POST /login HTTP/1.1" 401 128 "-" "Mozilla/5.0"
1.2.3.4 - - [01/Jan/2026:10:00:09 +0000] "POST /login HTTP/1.1" 401 128 "-" "Mozilla/5.0"
1.2.3.4 - - [01/Jan/2026:10:00:13 +0000] "POST /login HTTP/1.1" 401 128 "-" "Mozilla/5.0"
5.6.7.8 - - [01/Jan/2026:10:00:20 +0000] "GET /admin?q=1%27%20OR%201=1 HTTP/1.1" 403 512 "-" "sqlmap/1.0"
9.9.9.9 - - [01/Jan/2026:10:00:30 +0000] "GET /%2e%2e/etc/passwd HTTP/1.1" 500 64 "-" "curl/8.0"
garbage line that should be skipped
"""


class TestLogService:
    def test_parses_and_detects_anomalies(self):
        result = LogService.analyze_logs(SAMPLE_LOG)
        assert result["total_lines"] == 7
        assert result["parsed_lines"] == 6
        assert result["skipped_lines"] == 1
        assert result["anomalies_detected"] >= 6
        types = {a["type"] for a in result["anomalies"]}
        assert "failed_authentication" in types
        assert "sql_injection_attempt" in types
        assert "path_traversal_attempt" in types
        assert "suspicious_user_agent" in types
        assert "brute_force_pattern" in types
        assert "server_error" in types

    def test_threat_score_bounded(self):
        result = LogService.analyze_logs(SAMPLE_LOG)
        assert 0 <= result["threat_score"] <= 100
        assert result["severity"] in {"low", "medium", "high"}

    def test_clean_logs_low_score(self):
        clean = "\n".join(
            f'{i}.1.1.1 - - [01/Jan/2026:10:00:00 +0000] "GET /page/{i} HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
            for i in range(1, 6)
        )
        result = LogService.analyze_logs(clean)
        assert result["anomalies_detected"] == 0
        assert result["threat_score"] == 0
        assert result["severity"] == "low"

    def test_analyzer_marked_as_placeholder(self):
        result = LogService.analyze_logs("")
        assert result["analyzer"] == "deterministic-rule-based-placeholder"

    def test_non_string_rejected(self):
        with pytest.raises(Exception) as exc:
            LogService.analyze_logs(123)
        assert exc.value.status_code == 400

    def test_statistics_present(self):
        result = LogService.analyze_logs(SAMPLE_LOG)
        assert "status_code_counts" in result["stats"]
        assert result["stats"]["status_code_counts"].get(401) == 3
        assert result["stats"]["status_code_counts"].get(500) == 1


class TestLogEndpoint:
    def test_analyze_endpoint(self, client, auth_headers):
        response = client.post("/api/logs/analyze", json={"content": SAMPLE_LOG}, headers=auth_headers)
        assert response.status_code == 200
        body = response.get_json()
        assert body["success"] is True
        assert body["data"]["anomalies_detected"] >= 6

    def test_missing_content(self, client, auth_headers):
        response = client.post("/api/logs/analyze", json={}, headers=auth_headers)
        assert response.status_code == 400

    def test_oversized_content_rejected(self, client, auth_headers):
        response = client.post(
            "/api/logs/analyze", json={"content": "a" * 5000}, headers=auth_headers
        )
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"

    def test_non_json_body_rejected(self, client, auth_headers):
        response = client.post(
            "/api/logs/analyze", data="not json", content_type="text/plain", headers=auth_headers
        )
        assert response.status_code == 400


class TestLogPersistence:
    USER_ID = "44444444-4444-4444-8444-444444444444"

    def test_persists_completed_analysis(self, fake_supabase):
        result = LogService.analyze_logs(SAMPLE_LOG, user_id=self.USER_ID)
        payload = fake_supabase.inserts["log_scans"][-1]
        assert payload["user_id"] == self.USER_ID
        assert payload["event_count"] == result["parsed_lines"]
        assert payload["anomaly_count"] == result["anomalies_detected"]
        assert payload["findings"] == result["anomalies"]
        assert payload["risk_level"] == result["severity"]
        assert payload["model_version"] == "deterministic-rule-based-placeholder"
        assert set(payload) == {
            "user_id", "event_count", "anomaly_count",
            "findings", "risk_level", "model_version",
        }

    def test_never_persists_raw_log_content(self, fake_supabase):
        distinctive = (
            '9.9.9.9 - - [01/Jan/2026:10:00:40 +0000] '
            '"GET /distinctive-clean-page HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        )
        raw = SAMPLE_LOG + distinctive + "\n"
        LogService.analyze_logs(raw, user_id=self.USER_ID)
        payload = fake_supabase.inserts["log_scans"][-1]
        assert SAMPLE_LOG not in str(payload)
        assert distinctive not in str(payload)
        assert "content" not in payload

    def test_skips_persistence_without_user(self, fake_supabase):
        result = LogService.analyze_logs(SAMPLE_LOG)
        assert result["anomalies_detected"] >= 6
        assert "log_scans" not in fake_supabase.inserts

    def test_skips_persistence_when_client_unconfigured(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.log_service.get_user_supabase_client", lambda access_token=None: None
        )
        result = LogService.analyze_logs(SAMPLE_LOG, user_id=self.USER_ID)
        assert result["anomalies_detected"] >= 6

    def test_database_failure_raises_service_unavailable(self, fake_supabase):
        fake_supabase.fail_next_execute = True
        with pytest.raises(ServiceUnavailableError):
            LogService.analyze_logs(SAMPLE_LOG, user_id=self.USER_ID)


class TestLogPersistenceEndpoint:
    def test_analyze_endpoint_persists_scan(
        self, client, auth_headers, fake_supabase, auth_user_id
    ):
        response = client.post(
            "/api/logs/analyze", json={"content": SAMPLE_LOG}, headers=auth_headers
        )
        assert response.status_code == 200
        body = response.get_json()
        payload = fake_supabase.inserts["log_scans"][-1]
        assert payload["user_id"] == auth_user_id
        assert payload["event_count"] == body["data"]["parsed_lines"]
        assert payload["anomaly_count"] == body["data"]["anomalies_detected"]
        assert payload["risk_level"] == body["data"]["severity"]
        assert payload["model_version"] == body["data"]["analyzer"]

    def test_analyze_endpoint_ignores_user_id_from_body(
        self, client, auth_headers, auth_user_id, fake_supabase
    ):
        response = client.post(
            "/api/logs/analyze",
            json={
                "content": SAMPLE_LOG,
                "user_id": "99999999-9999-4999-8999-999999999999",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        payload = fake_supabase.inserts["log_scans"][-1]
        assert payload["user_id"] == auth_user_id

    def test_analyze_endpoint_database_failure_returns_503(
        self, client, auth_headers, fake_supabase
    ):
        fake_supabase.fail_next_execute = True
        response = client.post(
            "/api/logs/analyze", json={"content": SAMPLE_LOG}, headers=auth_headers
        )
        assert response.status_code == 503
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "SERVICE_UNAVAILABLE"
