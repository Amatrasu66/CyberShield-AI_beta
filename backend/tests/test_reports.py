"""Tests for the Supabase-backed report service, endpoints, and PDF generation.

The Supabase client (``fake_supabase``) and report storage service
(``report_storage``) are both mocked, so no network or filesystem side effects
escape the PDF rendering. PDF generation still runs against the real
:class:`PDFReportGenerator`.
"""

import pytest

from app.errors import ServiceUnavailableError, ValidationError
from app.reports.pdf_generator import PDFReportGenerator
from app.reports.storage import ReportStorageService
from app.services.report_service import ReportService

USER_ID = "33333333-3333-4333-8333-333333333333"
OTHER_USER_ID = "44444444-4444-4444-8444-444444444444"

STORAGE_URL = "https://storage.example/{path}?token=abc"


def _website_row(**overrides):
    row = {
        "id": "w-1",
        "user_id": USER_ID,
        "target_url": "https://example.com",
        "status": "completed",
        "security_score": 72,
        "risk_level": "medium",
        "findings": [
            {"name": "HTTPS enforcement", "status": "passed",
             "detail": "Site is served over HTTPS.", "recommendation": "Keep HTTPS as default."},
            {"name": "Content-Security-Policy", "status": "failed",
             "detail": "Header is missing.", "recommendation": "Set a CSP header."},
        ],
        "created_at": "2026-08-13T10:00:00+00:00",
    }
    row.update(overrides)
    return row


def _email_row(**overrides):
    row = {
        "id": "e-1",
        "user_id": USER_ID,
        "subject": "Verify your account",
        "sender_email": "support@example.com",
        "predicted_label": "suspicious",
        "confidence": 0.82,
        "risk_level": "suspicious",
        "indicators": [
            {"name": "Urgency language", "severity": "High", "evidence": "Contains urgent wording."},
        ],
        "model_version": "deterministic-heuristic-placeholder",
        "created_at": "2026-08-13T10:00:00+00:00",
    }
    row.update(overrides)
    return row


def _password_row(**overrides):
    row = {
        "id": "p-1",
        "user_id": USER_ID,
        "password_length": 10,
        "entropy": 45.2,
        "strength_score": 62,
        "strength_label": "Fair",
        "has_upper": True,
        "has_lower": True,
        "has_number": True,
        "has_symbol": False,
        "breached": False,
        "created_at": "2026-08-13T10:00:00+00:00",
    }
    row.update(overrides)
    return row


def _log_row(**overrides):
    row = {
        "id": "l-1",
        "user_id": USER_ID,
        "event_count": 110,
        "anomaly_count": 2,
        "findings": [
            {"line_number": 12, "type": "failed_authentication", "severity": "High",
             "evidence": "HTTP 401 from 192.168.1.5 on /admin"},
        ],
        "risk_level": "medium",
        "model_version": "deterministic-rule-based-placeholder",
        "created_at": "2026-08-13T10:00:00+00:00",
    }
    row.update(overrides)
    return row


def _report_row(report_id="r-1", user_id=USER_ID, **overrides):
    row = {
        "id": report_id,
        "user_id": user_id,
        "title": "Weekly Security Audit",
        "report_type": "pdf",
        "storage_path": f"{user_id}/{report_id}.pdf",
        "report_data": {"title": "Weekly Security Audit", "website_scan": None},
        "created_at": "2026-08-13T10:30:00+00:00",
    }
    row.update(overrides)
    return row


def _full_report_data():
    return {
        "title": "Weekly Security Audit",
        "id": "report-123",
        "generated_at": "2026-08-13T10:30:00+00:00",
        "summary": "Overall posture is acceptable but several improvements are recommended.",
        "website_scan": {
            "target": "https://example.com",
            "final_url": "https://example.com/",
            "final_status_code": 200,
            "score": 72,
            "grade": "C",
            "scan_duration_ms": 345.2,
            "summary": "3 passed, 2 failed, 1 warning(s) out of 6 checks.",
            "checks": [
                {"name": "HTTPS enforcement", "status": "passed",
                 "detail": "Site is served over HTTPS.", "recommendation": "Keep HTTPS as default."},
                {"name": "Content-Security-Policy", "status": "failed",
                 "detail": "Header is missing.", "recommendation": "Set a CSP header."},
                {"name": "CORS policy", "status": "warning",
                 "detail": "Access-Control-Allow-Origin is '*'.", "recommendation": "Restrict CORS."},
            ],
        },
        "email_scan": {
            "subject": "Verify your account",
            "sender_email": "support@example.com",
            "risk_level": "suspicious",
            "risk_score": 55,
            "confidence": 0.82,
            "predicted_label": "suspicious",
            "summary": "Elevated risk: some indicators warrant review.",
            "indicators": [
                {"name": "Urgency language", "severity": "High",
                 "evidence": "Contains urgent wording."},
                {"name": "Generic greeting", "severity": "Low",
                 "evidence": "Non-personalized greeting."},
            ],
        },
        "password_scan": {
            "length": 10,
            "char_classes": ["lowercase", "uppercase", "digits"],
            "entropy_bits": 45.2,
            "crack_time_estimate": "days",
            "in_common_list": False,
            "strength_score": 62,
            "strength": "Fair",
            "recommendations": [
                {"text": "Add numbers and special characters.", "priority": 4},
                {"text": "Consider a password manager.", "priority": 7},
            ],
        },
        "log_scan": {
            "total_lines": 120,
            "parsed_lines": 110,
            "anomalies_detected": 2,
            "threat_score": 34,
            "severity": "medium",
            "summary": "Analyzed 110 log line(s); 2 anomaly(ies) detected.",
            "stats": {"unique_ips": 14, "top_sources": [("192.168.1.5", 9), ("10.0.0.1", 4)]},
            "anomalies": [
                {"line_number": 12, "type": "failed_authentication", "severity": "High",
                 "evidence": "HTTP 401 from 192.168.1.5 on /admin"},
                {"line_number": 88, "type": "server_error", "severity": "Medium",
                 "evidence": "HTTP 500 on /api"},
            ],
        },
        "findings": [
            {"severity": "high", "source": "Report",
             "description": "CSP header missing site-wide.", "recommendation": "Deploy a CSP."},
        ],
    }


def _assert_valid_pdf(path):
    raw = path.read_bytes()
    assert raw.startswith(b"%PDF-")
    assert b"%%EOF" in raw
    assert len(raw) > 1000


@pytest.fixture()
def report_storage(monkeypatch):
    """Replace storage I/O with a deterministic in-memory fake."""
    state = {"uploads": [], "signed": []}

    def fake_upload(pdf_file, user_id, report_id, config=None):
        state["uploads"].append((pdf_file, user_id, report_id))
        return {
            "storage_path": f"{user_id}/{report_id}.pdf",
            "signed_url": STORAGE_URL.format(path=f"{user_id}/{report_id}.pdf"),
        }

    def fake_signed_url(user_id, report_id, config=None):
        state["signed"].append((user_id, report_id))
        return STORAGE_URL.format(path=f"{user_id}/{report_id}.pdf")

    monkeypatch.setattr(ReportStorageService, "upload_pdf", staticmethod(fake_upload))
    monkeypatch.setattr(ReportStorageService, "get_signed_url", staticmethod(fake_signed_url))
    return state


class TestReportService:
    def test_generates_from_scan_data(self, fake_supabase, report_storage):
        fake_supabase.seed("website_scans", [_website_row()])
        fake_supabase.seed("email_scans", [_email_row()])
        fake_supabase.seed("password_scans", [_password_row()])
        fake_supabase.seed("log_scans", [_log_row()])

        report = ReportService.generate_report({"title": "Audit"}, user_id=USER_ID)

        assert report["user_id"] == USER_ID
        assert report["title"] == "Audit"
        assert report["report_type"] == "pdf"
        assert report["storage_path"] == f"{USER_ID}/{report['id']}.pdf"
        assert report["signed_url"] == STORAGE_URL.format(path=f"{USER_ID}/{report['id']}.pdf")
        assert report["report_data"]["website_scan"]["target"] == "https://example.com"
        assert report["report_data"]["website_scan"]["score"] == 72
        assert report["report_data"]["email_scan"]["subject"] == "Verify your account"
        assert report["report_data"]["password_scan"]["strength_score"] == 62
        assert report["report_data"]["log_scan"]["anomaly_count"] == 2

    def test_persists_report_row(self, fake_supabase, report_storage):
        fake_supabase.seed("website_scans", [_website_row()])

        report = ReportService.generate_report({"title": "Audit"}, user_id=USER_ID)

        payload = fake_supabase.inserts["reports"][-1]
        assert payload["id"] == report["id"]
        assert payload["user_id"] == USER_ID
        assert payload["title"] == "Audit"
        assert payload["report_type"] == "pdf"
        assert payload["storage_path"] == f"{USER_ID}/{report['id']}.pdf"
        assert payload["report_data"]["website_scan"]["target"] == "https://example.com"
        assert set(payload) == {
            "id", "user_id", "title", "report_type", "storage_path", "report_data",
        }

    def test_uploads_real_pdf_bytes(self, fake_supabase, report_storage):
        fake_supabase.seed("email_scans", [_email_row()])

        report = ReportService.generate_report({"title": "Audit"}, user_id=USER_ID)

        assert len(report_storage["uploads"]) == 1
        pdf_bytes, uploaded_user, uploaded_id = report_storage["uploads"][0]
        assert uploaded_user == USER_ID
        assert uploaded_id == report["id"]
        assert pdf_bytes.startswith(b"%PDF-")

    def test_ignores_user_id_in_config(self, fake_supabase, report_storage):
        fake_supabase.seed("website_scans", [_website_row()])

        report = ReportService.generate_report(
            {"title": "Audit", "user_id": "99999999-9999-4999-8999-999999999999"},
            user_id=USER_ID,
        )

        assert report["user_id"] == USER_ID
        assert fake_supabase.inserts["reports"][-1]["user_id"] == USER_ID

    def test_requires_user_id(self, report_storage):
        with pytest.raises(ValidationError):
            ReportService.generate_report({"title": "Audit"})

    def test_empty_title_rejected(self, report_storage):
        with pytest.raises(ValidationError) as exc:
            ReportService.generate_report({"title": ""}, user_id=USER_ID)
        assert exc.value.status_code == 400

    def test_title_too_long_rejected(self, report_storage):
        with pytest.raises(ValidationError) as exc:
            ReportService.generate_report({"title": "x" * 201}, user_id=USER_ID)
        assert exc.value.status_code == 400

    def test_default_title(self, fake_supabase, report_storage):
        report = ReportService.generate_report({}, user_id=USER_ID)
        assert report["title"] == "Security Audit Report"

    def test_findings_must_be_list(self, report_storage):
        with pytest.raises(ValidationError) as exc:
            ReportService.generate_report(
                {"title": "X", "findings": "oops"}, user_id=USER_ID
            )
        assert exc.value.status_code == 400

    def test_summary_override(self, fake_supabase, report_storage):
        report = ReportService.generate_report(
            {"title": "X", "summary": "Custom summary"}, user_id=USER_ID
        )
        assert report["report_data"]["summary"] == "Custom summary"

    def test_findings_passthrough(self, fake_supabase, report_storage):
        findings = [{"severity": "high", "source": "Report", "description": "Something"}]
        report = ReportService.generate_report(
            {"title": "X", "findings": findings}, user_id=USER_ID
        )
        assert report["report_data"]["findings"] == findings

    def test_no_scans_still_generates_report(self, fake_supabase, report_storage):
        report = ReportService.generate_report({"title": "Empty"}, user_id=USER_ID)

        assert report["report_data"]["website_scan"] is None
        assert report["report_data"]["email_scan"] is None
        assert report["report_data"]["password_scan"] is None
        assert report["report_data"]["log_scan"] is None
        assert "no prior scan history" in report["report_data"]["summary"]

    def test_supabase_unconfigured_raises(self, monkeypatch, report_storage):
        monkeypatch.setattr(
            "app.services.report_service.get_user_supabase_client", lambda access_token=None: None
        )
        with pytest.raises(ServiceUnavailableError) as exc:
            ReportService.generate_report({"title": "X"}, user_id=USER_ID)
        assert exc.value.status_code == 503

    def test_scan_read_failure_raises(self, fake_supabase, report_storage):
        fake_supabase.fail_next_execute = True
        with pytest.raises(ServiceUnavailableError):
            ReportService.generate_report({"title": "X"}, user_id=USER_ID)

    def test_insert_failure_raises(self, fake_supabase, report_storage):
        fake_supabase.seed("website_scans", [_website_row()])
        fake_supabase.fail_inserts = True
        with pytest.raises(ServiceUnavailableError) as exc:
            ReportService.generate_report({"title": "X"}, user_id=USER_ID)
        assert exc.value.status_code == 503


class TestReportServiceListing:
    def test_lists_own_reports_with_signed_urls(self, fake_supabase, report_storage):
        fake_supabase.seed("reports", [
            _report_row(report_id="r-1", user_id=USER_ID),
            _report_row(report_id="r-2", user_id=USER_ID, title="Second"),
        ])

        reports = ReportService.list_reports(user_id=USER_ID)

        assert [r["title"] for r in reports] == ["Weekly Security Audit", "Second"]
        assert reports[0]["signed_url"] == STORAGE_URL.format(path=f"{USER_ID}/r-1.pdf")
        assert reports[1]["signed_url"] == STORAGE_URL.format(path=f"{USER_ID}/r-2.pdf")
        assert len(report_storage["signed"]) == 2

    def test_lists_only_own_reports(self, fake_supabase, report_storage):
        fake_supabase.seed("reports", [
            _report_row(report_id="r-mine", user_id=USER_ID, title="Mine"),
            _report_row(report_id="r-other", user_id=OTHER_USER_ID, title="Theirs"),
        ])

        reports = ReportService.list_reports(user_id=USER_ID)

        assert len(reports) == 1
        assert reports[0]["title"] == "Mine"

    def test_empty_list(self, fake_supabase, report_storage):
        assert ReportService.list_reports(user_id=USER_ID) == []

    def test_requires_user_id(self, report_storage):
        with pytest.raises(ValidationError):
            ReportService.list_reports()

    def test_supabase_unconfigured_raises(self, monkeypatch, report_storage):
        monkeypatch.setattr(
            "app.services.report_service.get_user_supabase_client", lambda access_token=None: None
        )
        with pytest.raises(ServiceUnavailableError):
            ReportService.list_reports(user_id=USER_ID)

    def test_database_failure_raises(self, fake_supabase, report_storage):
        fake_supabase.fail_next_execute = True
        with pytest.raises(ServiceUnavailableError):
            ReportService.list_reports(user_id=USER_ID)


class TestReportEndpoints:
    def test_generate_endpoint(self, client, auth_headers, auth_user_id, fake_supabase, report_storage):
        fake_supabase.seed("website_scans", [_website_row(user_id=auth_user_id)])
        response = client.post(
            "/api/reports/generate", json={"title": "Weekly audit"}, headers=auth_headers
        )
        assert response.status_code == 201
        body = response.get_json()
        assert body["success"] is True
        assert body["data"]["title"] == "Weekly audit"
        assert body["data"]["signed_url"].startswith("https://storage.example/")

    def test_generate_endpoint_ignores_user_id_in_body(
        self, client, auth_headers, auth_user_id, fake_supabase, report_storage
    ):
        fake_supabase.seed("website_scans", [_website_row(user_id=auth_user_id)])
        response = client.post(
            "/api/reports/generate",
            json={"title": "Weekly audit", "user_id": "99999999-9999-4999-8999-999999999999"},
            headers=auth_headers,
        )
        assert response.status_code == 201
        payload = fake_supabase.inserts["reports"][-1]
        assert payload["user_id"] == auth_user_id

    def test_list_endpoint(self, client, auth_headers, auth_user_id, fake_supabase, report_storage):
        fake_supabase.seed("reports", [_report_row(user_id=auth_user_id)])
        response = client.get("/api/reports", headers=auth_headers)
        assert response.status_code == 200
        body = response.get_json()
        assert body["meta"]["count"] == 1
        assert body["data"][0]["title"] == "Weekly Security Audit"
        assert body["data"][0]["signed_url"].startswith("https://storage.example/")

    def test_list_only_returns_own_reports(
        self, client, auth_headers, auth_user_id, fake_supabase, report_storage
    ):
        fake_supabase.seed("reports", [
            _report_row(report_id="r-mine", user_id=auth_user_id, title="Mine"),
            _report_row(report_id="r-other", user_id=OTHER_USER_ID, title="Theirs"),
        ])
        response = client.get("/api/reports", headers=auth_headers)
        body = response.get_json()
        assert body["meta"]["count"] == 1
        assert body["data"][0]["title"] == "Mine"

    def test_list_empty(self, client, auth_headers, report_storage):
        response = client.get("/api/reports", headers=auth_headers)
        assert response.status_code == 200
        assert response.get_json()["meta"]["count"] == 0

    def test_generate_invalid_payload(self, client, auth_headers, report_storage):
        response = client.post(
            "/api/reports/generate", json={"title": 123}, headers=auth_headers
        )
        assert response.status_code == 400

    def test_generate_database_failure_returns_503(
        self, client, auth_headers, fake_supabase, report_storage
    ):
        fake_supabase.fail_inserts = True
        response = client.post(
            "/api/reports/generate", json={"title": "Weekly audit"}, headers=auth_headers
        )
        assert response.status_code == 503
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "SERVICE_UNAVAILABLE"

    def test_list_database_failure_returns_503(
        self, client, auth_headers, fake_supabase, report_storage
    ):
        fake_supabase.fail_next_execute = True
        response = client.get("/api/reports", headers=auth_headers)
        assert response.status_code == 503
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "SERVICE_UNAVAILABLE"


class TestPDFReportGenerator:
    def test_generate_pdf_creates_valid_file(self, tmp_path):
        output = tmp_path / "report.pdf"
        result = PDFReportGenerator.generate_pdf(_full_report_data(), str(output))
        assert result == str(output)
        assert output.exists()
        _assert_valid_pdf(output)

    def test_generate_pdf_returns_output_path(self, tmp_path):
        output = tmp_path / "nested" / "report.pdf"
        result = PDFReportGenerator.generate_pdf(_full_report_data(), str(output))
        assert result == str(output)
        assert output.parent.exists()

    def test_generate_pdf_empty_report_data(self, tmp_path):
        output = tmp_path / "empty.pdf"
        result = PDFReportGenerator.generate_pdf({}, str(output))
        assert result == str(output)
        _assert_valid_pdf(output)

    def test_generate_pdf_none_report_data(self, tmp_path):
        output = tmp_path / "none.pdf"
        result = PDFReportGenerator.generate_pdf(None, str(output))
        assert result == str(output)
        _assert_valid_pdf(output)

    def test_generate_pdf_missing_sections(self, tmp_path):
        data = _full_report_data()
        for key in ("website_scan", "email_scan", "password_scan", "log_scan", "findings"):
            data[key] = None
        output = tmp_path / "missing.pdf"
        result = PDFReportGenerator.generate_pdf(data, str(output))
        _assert_valid_pdf(output)
        assert b"No website scan data was included in this report." in output.read_bytes()

    def test_generate_pdf_partial_sections(self, tmp_path):
        data = {"title": "Website only", "website_scan": _full_report_data()["website_scan"]}
        output = tmp_path / "partial.pdf"
        result = PDFReportGenerator.generate_pdf(data, str(output))
        _assert_valid_pdf(output)

    def test_generate_pdf_contains_section_headings(self, tmp_path):
        output = tmp_path / "headings.pdf"
        PDFReportGenerator.generate_pdf(_full_report_data(), str(output))
        raw = output.read_bytes()
        for heading in (
            "1. Overall Security Summary",
            "2. Website Security Scan",
            "3. Email Security Scan",
            "4. Password Strength Analysis",
            "5. Log Analysis",
            "6. Risk & Findings Summary",
            "CYBERSHIELD AI",
        ):
            assert heading in raw.decode("latin-1")

    def test_generate_pdf_requires_dict(self, tmp_path):
        with pytest.raises(ValueError):
            PDFReportGenerator.generate_pdf(["not", "a", "dict"], str(tmp_path / "x.pdf"))

    def test_generate_pdf_requires_output_path(self):
        with pytest.raises(ValueError):
            PDFReportGenerator.generate_pdf({}, None)
