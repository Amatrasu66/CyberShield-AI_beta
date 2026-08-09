"""Tests for the in-memory report service and endpoints."""

import pytest

from app.services.report_service import ReportService


class TestReportService:
    def test_generate_report(self):
        report = ReportService.generate_report({"title": "Audit", "findings": [{"name": "A"}]})
        assert report["id"]
        assert report["title"] == "Audit"
        assert report["finding_count"] == 1
        assert report["storage"] == "in-memory"
        assert report["persistence"] == "pending-supabase"

    def test_list_reports(self):
        ReportService.clear_reports()
        ReportService.generate_report({"title": "One"})
        ReportService.generate_report({"title": "Two"})
        reports = ReportService.list_reports()
        assert len(reports) == 2

    def test_empty_title_rejected(self):
        with pytest.raises(Exception) as exc:
            ReportService.generate_report({"title": ""})
        assert exc.value.status_code == 400

    def test_findings_must_be_list(self):
        with pytest.raises(Exception) as exc:
            ReportService.generate_report({"title": "X", "findings": "oops"})
        assert exc.value.status_code == 400

    def test_default_title(self):
        report = ReportService.generate_report({})
        assert report["title"] == "Security Audit Report"


class TestReportEndpoints:
    def test_generate_endpoint(self, client):
        response = client.post("/api/reports/generate", json={"title": "Weekly audit"})
        assert response.status_code == 201
        body = response.get_json()
        assert body["success"] is True
        assert body["data"]["title"] == "Weekly audit"

    def test_list_endpoint(self, client):
        client.post("/api/reports/generate", json={"title": "A"})
        response = client.get("/api/reports")
        assert response.status_code == 200
        body = response.get_json()
        assert body["meta"]["count"] == 1
        assert body["data"][0]["title"] == "A"

    def test_list_empty(self, client):
        response = client.get("/api/reports")
        assert response.status_code == 200
        assert response.get_json()["meta"]["count"] == 0

    def test_generate_invalid_payload(self, client):
        response = client.post("/api/reports/generate", json={"title": 123})
        assert response.status_code == 400
