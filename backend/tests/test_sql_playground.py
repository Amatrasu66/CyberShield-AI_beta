"""Tests for the SQL injection playground service and endpoint."""

import pytest

from app.errors import ValidationError
from app.services.sql_service import SQLPlaygroundService


class TestSQLPlaygroundService:
    def test_benign_input(self):
        result = SQLPlaygroundService.run_demo("alice")
        assert result["vulnerable_pattern_detected"] is False
        assert result["outcome"] == "blocked_by_parameterization"
        assert result["detected_patterns"] == []

    def test_injection_input_detected(self):
        result = SQLPlaygroundService.run_demo("' OR '1'='1")
        assert result["vulnerable_pattern_detected"] is True
        assert "boolean_or" in result["detected_patterns"]
        assert "single_quote" in result["detected_patterns"]
        # Unsafe rendering must visibly alter the query.
        assert "'1'='1" in result["unsafe_query"]

    def test_sql_comment_detected(self):
        result = SQLPlaygroundService.run_demo("admin' --")
        assert result["vulnerable_pattern_detected"] is True
        assert "sql_comment" in result["detected_patterns"]

    def test_union_select_detected(self):
        result = SQLPlaygroundService.run_demo("1 UNION SELECT username, password FROM users")
        assert "union_select" in result["detected_patterns"]

    def test_parameterized_explanation_present(self):
        result = SQLPlaygroundService.run_demo("' OR '1'='1")
        assert result["explanations"]["parameterized"]
        assert result["explanations"]["security"]
        assert result["explanations"]["example"]["input"]

    def test_no_sql_is_executed(self):
        # The result must never contain results suggesting real execution.
        result = SQLPlaygroundService.run_demo("' OR '1'='1")
        assert "rows returned" not in result["unsafe_query"]
        assert "SELECT" not in result.get("outcome", "")

    def test_validate_input_limits(self):
        with pytest.raises(ValidationError):
            SQLPlaygroundService.validate_input("x" * 5000, max_length=100)
        assert SQLPlaygroundService.validate_input("ok", max_length=100) == "ok"

    def test_validate_input_rejects_non_string(self):
        with pytest.raises(ValidationError):
            SQLPlaygroundService.validate_input(12345, max_length=100)


class TestSQLEndpoint:
    def test_demo_endpoint(self, client):
        response = client.post("/api/sql/demo", json={"input": "' OR '1'='1"})
        assert response.status_code == 200
        body = response.get_json()
        assert body["success"] is True
        assert body["data"]["vulnerable_pattern_detected"] is True

    def test_demo_endpoint_missing_input(self, client):
        response = client.post("/api/sql/demo", json={})
        assert response.status_code == 400

    def test_demo_endpoint_empty_string(self, client):
        response = client.post("/api/sql/demo", json={"input": ""})
        assert response.status_code == 200
        assert response.get_json()["data"]["vulnerable_pattern_detected"] is False

    def test_demo_endpoint_missing_json(self, client):
        response = client.post("/api/sql/demo")
        assert response.status_code == 400
