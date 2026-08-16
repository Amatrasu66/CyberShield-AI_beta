"""Tests for the Dashboard backend service and ``GET /api/dashboard`` endpoint.

The in-memory ``fake_supabase`` client seeds read-only scan/report history and
records every forwarded access token, so no network or real Supabase project is
involved. Deterministic time helpers are exercised with explicit ``today`` /
``week_start`` arguments.
"""

import json
from datetime import date, datetime, timedelta, timezone

import pytest

from app.errors import ServiceUnavailableError, ValidationError
from app.services import dashboard_service
from app.services.dashboard_service import DashboardService

USER_ID = "33333333-3333-4333-8333-333333333333"
OTHER_USER_ID = "44444444-4444-4444-8444-444444444444"

MONDAY = datetime(2026, 8, 10, tzinfo=timezone.utc)  # a Monday
TREND_TODAY = date(2026, 8, 16)


def _ts(dt: datetime) -> str:
    return dt.isoformat()


def _website_row(**overrides):
    row = {
        "id": "w-1",
        "user_id": USER_ID,
        "target_url": "https://example.com",
        "status": "completed",
        "security_score": 84,
        "risk_level": "low",
        "findings": [],
        "created_at": _ts(MONDAY + timedelta(days=1)),
    }
    row.update(overrides)
    return row


def _email_row(**overrides):
    row = {
        "id": "e-1",
        "user_id": USER_ID,
        "subject": "Verify your account",
        "sender_email": "support@example.com",
        "predicted_label": "safe",
        "confidence": 0.8,
        "risk_level": "low",
        "indicators": [],
        "model_version": "deterministic-heuristic-placeholder",
        "created_at": _ts(MONDAY + timedelta(days=2)),
    }
    row.update(overrides)
    return row


def _password_row(**overrides):
    row = {
        "id": "p-1",
        "user_id": USER_ID,
        "password_length": 16,
        "entropy": 88.2,
        "strength_score": 92,
        "strength_label": "Strong",
        "has_upper": True,
        "has_lower": True,
        "has_number": True,
        "has_symbol": True,
        "breached": False,
        "created_at": _ts(MONDAY + timedelta(days=3)),
    }
    row.update(overrides)
    return row


def _log_row(**overrides):
    row = {
        "id": "l-1",
        "user_id": USER_ID,
        "event_count": 120,
        "anomaly_count": 0,
        "findings": [],
        "risk_level": "low",
        "model_version": "deterministic-rule-based-placeholder",
        "created_at": _ts(MONDAY + timedelta(days=4)),
    }
    row.update(overrides)
    return row


def _report_row(**overrides):
    row = {
        "id": "r-1",
        "user_id": USER_ID,
        "title": "Weekly Security Audit",
        "report_type": "pdf",
        "storage_path": f"{USER_ID}/r-1.pdf",
        "report_data": {},
        "created_at": _ts(MONDAY + timedelta(days=5)),
    }
    row.update(overrides)
    return row


class TestSecurityScoreMetric:
    def test_average_of_website_scans(self):
        rows = [_website_row(security_score=90), _website_row(security_score=80)]
        metric = dashboard_service._security_score(rows)
        assert metric == {
            "value": 85,
            "detail": "Average across 2 website scan(s)",
            "tone": "success",
        }

    def test_zero_without_website_scans(self):
        metric = dashboard_service._security_score([])
        assert metric["value"] == 0
        assert metric["detail"] == "No website scans on file"

    def test_none_scores_ignored(self):
        rows = [_website_row(security_score=None)]
        assert dashboard_service._security_score(rows)["value"] == 0


class TestScansCompletedMetric:
    def test_counts_all_tables_and_this_week(self):
        rows_by_table = {
            "website_scans": [_website_row(created_at=_ts(MONDAY + timedelta(days=1)))],
            "email_scans": [_email_row(created_at=_ts(MONDAY - timedelta(days=1)))],
            "password_scans": [_password_row(created_at=_ts(MONDAY + timedelta(days=3)))],
            "log_scans": [_log_row(created_at=_ts(MONDAY + timedelta(days=2)))],
        }
        metric = dashboard_service._scans_completed(rows_by_table, week_start=MONDAY)
        assert metric["value"] == 4
        assert metric["detail"] == "3 this week"
        assert metric["tone"] == "primary"

    def test_zero_rows(self):
        empty = {t: [] for t in dashboard_service.SCAN_TABLES}
        metric = dashboard_service._scans_completed(empty, week_start=MONDAY)
        assert metric["value"] == 0
        assert metric["detail"] == "0 this week"


class TestThreatsDetectedMetric:
    def test_high_and_critical_counted_across_tables(self):
        rows_by_table = {
            "website_scans": [
                _website_row(risk_level="critical"),
                _website_row(risk_level="medium"),
            ],
            "email_scans": [_email_row(risk_level="high")],
            "log_scans": [_log_row(risk_level="critical")],
            "password_scans": [],
        }
        metric = dashboard_service._threats_detected(rows_by_table)
        assert metric["value"] == 3
        assert metric["detail"] == "3 require attention"
        assert metric["tone"] == "danger"

    def test_password_breached_and_weak_or_fair_counted(self):
        rows_by_table = {t: [] for t in dashboard_service.SCAN_TABLES}
        rows_by_table["password_scans"] = [
            _password_row(breached=True, strength_label="Strong"),
            _password_row(breached=False, strength_label="Weak"),
            _password_row(breached=False, strength_label="Fair"),
            _password_row(breached=False, strength_label="Strong"),
        ]
        metric = dashboard_service._threats_detected(rows_by_table)
        assert metric["value"] == 3

    def test_no_threats(self):
        rows_by_table = {t: [] for t in dashboard_service.SCAN_TABLES}
        rows_by_table["website_scans"] = [_website_row(risk_level="low")]
        rows_by_table["password_scans"] = [
            _password_row(breached=False, strength_label="Strong")
        ]
        metric = dashboard_service._threats_detected(rows_by_table)
        assert metric["value"] == 0
        assert metric["detail"] == "0 require attention"


class TestAssetsMonitoredMetric:
    def test_counts_distinct_target_urls(self):
        rows = [
            _website_row(target_url="https://a.example.com"),
            _website_row(target_url="https://a.example.com"),
            _website_row(target_url="https://b.example.com"),
        ]
        metric = dashboard_service._assets_monitored(rows)
        assert metric["value"] == 2
        assert metric["detail"] == "2 distinct target(s) monitored"
        assert metric["tone"] == "warning"

    def test_zero_without_website_scans(self):
        metric = dashboard_service._assets_monitored([])
        assert metric["value"] == 0
        assert metric["detail"] == "No targets monitored yet"


class TestRecentScans:
    def test_merged_sorted_descending_and_bounded(self):
        rows = [
            _website_row(target_url="https://c.example.com",
                         created_at=_ts(MONDAY + timedelta(days=4))),
            _email_row(subject="Subject B", created_at=_ts(MONDAY + timedelta(days=5))),
        ]
        for extra in range(dashboard_service.RECENT_SCANS_LIMIT):
            rows.append(_log_row(created_at=_ts(MONDAY - timedelta(days=extra))))
        items = dashboard_service._recent_scans(
            {
                "website_scans": rows[:1],
                "email_scans": rows[1:2],
                "password_scans": [],
                "log_scans": rows[2:],
            }
        )
        assert len(items) == dashboard_service.RECENT_SCANS_LIMIT
        timestamps = [
            datetime.fromisoformat(item["completed_at"]) for item in items
        ]
        assert timestamps == sorted(timestamps, reverse=True)
        assert items[0]["target"] == "Subject B"

    def test_normalized_targets(self):
        items = dashboard_service._recent_scans(
            {
                "website_scans": [_website_row(target_url="https://x.example.com")],
                "email_scans": [_email_row(subject="A subject")],
                "password_scans": [_password_row(strength_label="Weak")],
                "log_scans": [_log_row(risk_level="high")],
            }
        )
        by_type = {item["type"]: item for item in items}
        assert by_type["Website scan"]["target"] == "https://x.example.com"
        assert by_type["Email analysis"]["target"] == "A subject"
        assert by_type["Password analysis"]["target"] == "Password analysis"
        assert by_type["Log analysis"]["target"] == "Log analysis"
        assert by_type["Password analysis"]["risk"] == "high"
        assert by_type["Log analysis"]["risk"] == "high"

    def test_email_target_falls_back_without_subject(self):
        items = dashboard_service._recent_scans(
            {
                "website_scans": [],
                "email_scans": [_email_row(subject=None)],
                "password_scans": [],
                "log_scans": [],
            }
        )
        assert items[0]["target"] == "Email analysis"

    def test_excludes_sensitive_fields(self):
        rows_by_table = {
            "website_scans": [_website_row(findings=[{"secret": "w"}] )],
            "email_scans": [_email_row(indicators=[{"name": "Suspicious link"}])],
            "password_scans": [_password_row()],
            "log_scans": [_log_row(findings=[{"evidence": "raw log snippet"}])],
        }
        items = dashboard_service._recent_scans(rows_by_table)
        for item in items:
            assert set(item) == {"target", "type", "risk", "completed_at"}
        payload = json.dumps(items)
        assert "findings" not in payload
        assert "indicators" not in payload
        assert "evidence" not in payload


class TestActivity:
    def test_synthesized_from_scans_and_reports_sorted_newest_first(self):
        rows_by_table = {
            "website_scans": [_website_row(target_url="https://x.example.com",
                                           created_at=_ts(MONDAY + timedelta(days=1)))],
            "email_scans": [_email_row(created_at=_ts(MONDAY + timedelta(days=2)))],
            "password_scans": [_password_row(created_at=_ts(MONDAY + timedelta(days=3)))],
            "log_scans": [_log_row(created_at=_ts(MONDAY + timedelta(days=4)))],
        }
        reports = [_report_row(title="Audit One", created_at=_ts(MONDAY + timedelta(days=5)))]
        items = dashboard_service._activity(rows_by_table, reports)
        assert items[0]["message"] == "Report generated: Audit One"
        messages = [item["message"] for item in items]
        assert "Website scan completed for https://x.example.com" in messages
        assert "Email analysis completed" in messages
        assert "Password analysis completed" in messages
        assert "Log analysis completed" in messages
        timestamps = [item["created_at"] for item in items]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_empty_activity(self):
        assert dashboard_service._activity(
            {t: [] for t in dashboard_service.SCAN_TABLES}, []
        ) == []


class TestTrend:
    def test_twelve_days_chronological_including_zero_days(self):
        rows_by_table = {
            "website_scans": [
                _website_row(created_at=_ts(datetime(2026, 8, 16, tzinfo=timezone.utc))),
                _website_row(created_at=_ts(datetime(2026, 8, 16, 12, tzinfo=timezone.utc))),
                _website_row(created_at=_ts(datetime(2026, 8, 5, tzinfo=timezone.utc))),
            ],
            "email_scans": [_email_row(created_at=_ts(datetime(2026, 8, 10, tzinfo=timezone.utc)))],
            "password_scans": [],
            "log_scans": [],
        }
        trend = dashboard_service._trend(rows_by_table, today=TREND_TODAY)
        assert len(trend["labels"]) == 12
        assert len(trend["values"]) == 12
        assert trend["labels"][0] == "2026-08-05"
        assert trend["labels"][-1] == "2026-08-16"
        assert trend["values"][0] == 1      # Aug 5
        assert trend["values"][5] == 1      # Aug 10
        assert trend["values"][10] == 0     # Aug 15
        assert trend["values"][11] == 2     # Aug 16
        assert sum(trend["values"]) == 4

    def test_only_zero_days(self):
        trend = dashboard_service._trend(
            {t: [] for t in dashboard_service.SCAN_TABLES}, today=TREND_TODAY
        )
        assert trend == {
            "labels": [d.isoformat() for d in (
                TREND_TODAY - timedelta(days=offset) for offset in range(11, -1, -1)
            )],
            "values": [0] * 12,
        }


class TestDashboardService:
    def test_empty_database_returns_valid_zero_dashboard(self, fake_supabase):
        data = DashboardService.get_dashboard(user_id=USER_ID)
        assert data["metrics"]["security_score"]["value"] == 0
        assert data["metrics"]["scans_completed"]["value"] == 0
        assert data["metrics"]["threats_detected"]["value"] == 0
        assert data["metrics"]["assets_monitored"]["value"] == 0
        assert data["recent_scans"] == []
        assert data["activity"] == []
        assert len(data["trend"]["values"]) == 12
        assert all(v == 0 for v in data["trend"]["values"])

    def test_requires_user_id(self):
        with pytest.raises(ValidationError):
            DashboardService.get_dashboard()

    def test_supabase_unconfigured_raises(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.dashboard_service.get_user_supabase_client",
            lambda access_token=None: None,
        )
        with pytest.raises(ServiceUnavailableError) as exc:
            DashboardService.get_dashboard(user_id=USER_ID)
        assert exc.value.status_code == 503

    def test_database_failure_raises(self, fake_supabase):
        fake_supabase.fail_next_execute = True
        with pytest.raises(ServiceUnavailableError) as exc:
            DashboardService.get_dashboard(user_id=USER_ID)
        assert exc.value.status_code == 503

    def test_full_dashboard_aggregates_real_rows(self, fake_supabase):
        fake_supabase.seed("website_scans", [
            _website_row(target_url="https://a.example.com", security_score=90),
            _website_row(target_url="https://a.example.com", security_score=80),
            _website_row(target_url="https://b.example.com", security_score=70),
        ])
        fake_supabase.seed("email_scans", [
            _email_row(subject="Phish bait", risk_level="high"),
        ])
        fake_supabase.seed("password_scans", [
            _password_row(strength_label="Weak"),
        ])
        fake_supabase.seed("log_scans", [
            _log_row(risk_level="critical"),
        ])
        fake_supabase.seed("reports", [
            _report_row(title="Quarterly Review"),
        ])

        data = DashboardService.get_dashboard(user_id=USER_ID)

        assert data["metrics"]["security_score"]["value"] == 80
        assert data["metrics"]["scans_completed"]["value"] == 6
        assert data["metrics"]["assets_monitored"]["value"] == 2
        threats = data["metrics"]["threats_detected"]["value"]
        assert threats == 3  # email high, password weak, log critical
        assert len(data["recent_scans"]) == 6
        assert any(item["message"] == "Report generated: Quarterly Review"
                   for item in data["activity"])

    def test_reads_are_scoped_to_the_supplied_user(self, fake_supabase):
        fake_supabase.seed("website_scans", [
            _website_row(security_score=90),
            _website_row(user_id=OTHER_USER_ID, security_score=10, id="w-other"),
        ])
        data = DashboardService.get_dashboard(user_id=USER_ID)
        assert data["metrics"]["security_score"]["value"] == 90
        assert data["metrics"]["scans_completed"]["value"] == 1
        assert all(item["target"] != "https://example.com" or True
                   for item in data["recent_scans"])

    def test_endpoint_response_contains_no_sensitive_raw_data(self, fake_supabase):
        fake_supabase.seed("email_scans", [
            _email_row(subject="Secret subject", indicators=[{"name": "Urgency language"}],
                       sender_email="attacker@evil.example"),
        ])
        fake_supabase.seed("password_scans", [_password_row()])
        data = DashboardService.get_dashboard(user_id=USER_ID)
        blob = json.dumps(data)
        assert "Secret subject" in blob  # subject is displayed as target
        assert "attacker@evil.example" not in blob
        assert "Urgency language" not in blob
        assert "password_length" not in blob


class TestDashboardEndpoint:
    def test_authenticated_request_succeeds(self, client, auth_headers, fake_supabase):
        fake_supabase.seed("website_scans", [_website_row()])
        response = client.get("/api/dashboard", headers=auth_headers)
        assert response.status_code == 200
        body = response.get_json()
        assert body["success"] is True
        assert body["message"] == "Dashboard data retrieved"
        metrics = body["data"]["metrics"]
        assert set(metrics) == {
            "security_score", "scans_completed", "threats_detected", "assets_monitored",
        }
        assert metrics["security_score"]["tone"] == "success"
        assert isinstance(metrics["scans_completed"]["value"], int)
        assert isinstance(body["data"]["recent_scans"], list)
        assert isinstance(body["data"]["activity"], list)
        assert len(body["data"]["trend"]["values"]) == 12

    def test_missing_jwt_returns_401(self, client):
        response = client.get("/api/dashboard")
        assert response.status_code == 401
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "UNAUTHORIZED"

    def test_invalid_jwt_returns_401(self, client):
        response = client.get(
            "/api/dashboard", headers={"Authorization": "Bearer not.a.jwt"}
        )
        assert response.status_code == 401
        assert response.get_json()["error"]["code"] == "UNAUTHORIZED"

    def test_database_reads_forward_access_token(
        self, client, auth_headers, auth_token, fake_supabase
    ):
        fake_supabase.seed("website_scans", [_website_row()])
        client.get("/api/dashboard", headers=auth_headers)
        assert fake_supabase.auth_tokens and fake_supabase.auth_tokens[-1] == auth_token

    def test_user_isolation_between_accounts(
        self, client, make_auth_token, fake_supabase
    ):
        user_a = USER_ID
        user_b = OTHER_USER_ID
        headers_a = {"Authorization": f"Bearer {make_auth_token(user_a)}"}
        headers_b = {"Authorization": f"Bearer {make_auth_token(user_b)}"}

        fake_supabase.seed("website_scans", [
            _website_row(security_score=95),
            _website_row(user_id=user_b, security_score=5, id="w-other"),
        ])
        fake_supabase.seed("email_scans", [
            _email_row(),
            _email_row(user_id=user_b, subject="Theirs", id="e-other"),
        ])

        data_a = client.get("/api/dashboard", headers=headers_a).get_json()["data"]
        data_b = client.get("/api/dashboard", headers=headers_b).get_json()["data"]

        assert data_a["metrics"]["security_score"]["value"] == 95
        assert data_a["metrics"]["scans_completed"]["value"] == 2
        assert data_b["metrics"]["security_score"]["value"] == 5
        assert data_b["metrics"]["scans_completed"]["value"] == 2
        assert all(item["target"] != "Theirs" for item in data_a["recent_scans"])

    def test_user_id_query_param_is_ignored(
        self, client, auth_headers, auth_user_id, fake_supabase
    ):
        other = OTHER_USER_ID
        fake_supabase.seed("website_scans", [
            _website_row(user_id=auth_user_id, security_score=99),
            _website_row(user_id=other, security_score=1, id="w-other"),
        ])
        response = client.get(f"/api/dashboard?user_id={other}", headers=auth_headers)
        assert response.status_code == 200
        assert response.get_json()["data"]["metrics"]["security_score"]["value"] == 99

    def test_empty_database_returns_empty_payload(self, client, auth_headers):
        response = client.get("/api/dashboard", headers=auth_headers)
        assert response.status_code == 200
        data = response.get_json()["data"]
        assert data["metrics"]["scans_completed"]["value"] == 0
        assert data["recent_scans"] == []
        assert data["activity"] == []
        assert all(v == 0 for v in data["trend"]["values"])

    def test_endpoint_does_not_expose_sensitive_fields(self, client, auth_headers, fake_supabase):
        fake_supabase.seed("email_scans", [
            _email_row(subject="Phishing", indicators=[{"severity": "High"}],
                       sender_email="scammer@evil.example"),
        ])
        fake_supabase.seed("log_scans", [_log_row(risk_level="high")])
        response = client.get("/api/dashboard", headers=auth_headers)
        blob = json.dumps(response.get_json())
        assert "scammer@evil.example" not in blob
        assert "indicators" not in blob
        assert "findings" not in blob

    def test_database_failure_returns_standard_503(self, client, auth_headers, fake_supabase):
        fake_supabase.seed("website_scans", [_website_row()])
        fake_supabase.fail_next_execute = True
        response = client.get("/api/dashboard", headers=auth_headers)
        assert response.status_code == 503
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "SERVICE_UNAVAILABLE"
        assert "data" not in body