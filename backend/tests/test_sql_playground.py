"""Tests for the SQL injection playground service and endpoints (Phase 1 + 2)."""

import pytest

from app.errors import ValidationError
from app.services.sql_lab_service import SQL_PAYLOAD_MAX_LENGTH, SCENARIOS, SQLLabService
from app.services.sql_service import SQLPlaygroundService

VALID_LOGIN_PAYLOAD = "' OR '1'='1"
VALID_BOOLEAN_PAYLOAD = "' AND 1=1 --"
VALID_UNION_PAYLOAD = "' UNION SELECT username, role FROM users --"
VALID_COMMENT_PAYLOAD = "admin'--"

SCENARIO_PAYLOADS = {
    "login": VALID_LOGIN_PAYLOAD,
    "union": VALID_UNION_PAYLOAD,
    "boolean": VALID_BOOLEAN_PAYLOAD,
    "comment": VALID_COMMENT_PAYLOAD,
}


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

    def test_demo_endpoint_remains_public(self, client):
        # Phase 2 must not change the existing /api/sql/demo behavior.
        response = client.post("/api/sql/demo", json={"input": "' OR '1'='1"})
        assert response.status_code == 200
        assert response.get_json()["success"] is True
        assert response.get_json()["data"]["vulnerable_pattern_detected"] is True


class TestSQLRunEndpoint:
    def test_run_valid_login_payload(self, client, auth_headers):
        response = client.post(
            "/api/sql/run",
            json={"scenario": "login", "payload": VALID_LOGIN_PAYLOAD},
            headers=auth_headers,
        )
        assert response.status_code == 200
        body = response.get_json()
        assert body["data"]["scenario"] == "login"
        assert body["data"]["vulnerable_result"]["rows"] == 3

    def test_run_valid_boolean_payload(self, client, auth_headers):
        response = client.post(
            "/api/sql/run",
            json={"scenario": "boolean", "payload": VALID_BOOLEAN_PAYLOAD},
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.get_json()["data"]["vulnerable_result"]["rows"] == 6

    def test_run_valid_union_payload(self, client, auth_headers):
        response = client.post(
            "/api/sql/run",
            json={"scenario": "union", "payload": VALID_UNION_PAYLOAD},
            headers=auth_headers,
        )
        assert response.status_code == 200
        body = response.get_json()
        assert body["data"]["scenario"] == "union"
        assert body["data"]["vulnerable_result"]["rows"] == 4

    def test_run_valid_comment_payload(self, client, auth_headers):
        response = client.post(
            "/api/sql/run",
            json={"scenario": "comment", "payload": VALID_COMMENT_PAYLOAD},
            headers=auth_headers,
        )
        assert response.status_code == 200
        body = response.get_json()
        assert body["data"]["scenario"] == "comment"
        assert body["data"]["vulnerable_result"]["data"][0][1:] == ["admin", "admin"]

    @pytest.mark.parametrize("scenario_id", sorted(SCENARIOS))
    def test_every_scenario_runs_through_the_endpoint(self, client, auth_headers, scenario_id):
        response = client.post(
            "/api/sql/run",
            json={"scenario": scenario_id, "payload": SCENARIO_PAYLOADS[scenario_id]},
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.get_json()["data"]["scenario"] == scenario_id

    def test_run_without_jwt_returns_401(self, client):
        response = client.post(
            "/api/sql/run", json={"scenario": "login", "payload": VALID_LOGIN_PAYLOAD}
        )
        assert response.status_code == 401
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "UNAUTHORIZED"

    def test_run_missing_scenario_returns_400(self, client, auth_headers):
        response = client.post(
            "/api/sql/run", json={"payload": VALID_LOGIN_PAYLOAD}, headers=auth_headers
        )
        assert response.status_code == 400

    def test_run_unknown_scenario_returns_400(self, client, auth_headers):
        response = client.post(
            "/api/sql/run", json={"scenario": "nope", "payload": "x"}, headers=auth_headers
        )
        assert response.status_code == 400

    def test_run_missing_payload_returns_400(self, client, auth_headers):
        response = client.post(
            "/api/sql/run", json={"scenario": "login"}, headers=auth_headers
        )
        assert response.status_code == 400

    def test_run_non_string_payload_returns_400(self, client, auth_headers):
        response = client.post(
            "/api/sql/run", json={"scenario": "login", "payload": 123}, headers=auth_headers
        )
        assert response.status_code == 400

    def test_run_non_string_scenario_returns_400(self, client, auth_headers):
        response = client.post(
            "/api/sql/run", json={"scenario": ["login"], "payload": "x"}, headers=auth_headers
        )
        assert response.status_code == 400

    def test_run_payload_over_limit_returns_400(self, client, auth_headers):
        response = client.post(
            "/api/sql/run",
            json={"scenario": "login", "payload": "a" * (SQL_PAYLOAD_MAX_LENGTH + 1)},
            headers=auth_headers,
        )
        assert response.status_code == 400
        body = response.get_json()
        assert body["error"]["code"] == "VALIDATION_ERROR"
        assert "maximum length" in body["message"]

    def test_run_empty_object_returns_400(self, client, auth_headers):
        response = client.post("/api/sql/run", json={}, headers=auth_headers)
        assert response.status_code == 400

    def test_arbitrary_sql_field_is_never_executed(self, client, auth_headers):
        response = client.post(
            "/api/sql/run", json={"query": "DROP TABLE users"}, headers=auth_headers
        )
        assert response.status_code == 400
        body = response.get_json()
        assert body["success"] is False
        assert "data" not in body

    def test_client_supplied_user_id_is_ignored(self, client, auth_headers, fake_supabase):
        response = client.post(
            "/api/sql/run",
            json={
                "scenario": "login",
                "payload": VALID_LOGIN_PAYLOAD,
                "user_id": "attacker-controlled-id",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        body = response.get_json()
        assert body["data"]["scenario"] == "login"
        assert body["data"]["input"] == VALID_LOGIN_PAYLOAD
        assert "user_id" not in body["data"]
        assert fake_supabase.inserts == {}
        assert fake_supabase.auth_tokens == []

    def test_standard_success_envelope(self, client, auth_headers):
        response = client.post(
            "/api/sql/run",
            json={"scenario": "login", "payload": VALID_LOGIN_PAYLOAD},
            headers=auth_headers,
        )
        assert response.status_code == 200
        body = response.get_json()
        assert body["success"] is True
        assert body["message"] == "SQL playground demo completed"
        assert body["data"]["scenario"] == "login"

    def test_result_preserves_sandbox_contract(self, client, auth_headers):
        response = client.post(
            "/api/sql/run",
            json={"scenario": "login", "payload": VALID_LOGIN_PAYLOAD},
            headers=auth_headers,
        )
        body = response.get_json()["data"]
        for key in (
            "scenario",
            "input",
            "vulnerable_query",
            "safe_query",
            "vulnerable_result",
            "safe_result",
            "explanation",
            "sandbox",
        ):
            assert key in body
        assert body["vulnerable_result"]["rows"] > 0
        assert body["safe_result"]["execution_status"] == "ok"
        assert body["explanation"]["why_vulnerable"]
        assert body["sandbox"] == "in-memory sqlite (isolated, non-persistent)"

    def test_no_supabase_client_accessed_by_sql_route(self, client, auth_headers, fake_supabase):
        response = client.post(
            "/api/sql/run",
            json={"scenario": "union", "payload": VALID_UNION_PAYLOAD},
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert fake_supabase.auth_tokens == []
        assert fake_supabase.inserts == {}

    def test_run_matches_service_result_exactly(self, client, auth_headers):
        response = client.post(
            "/api/sql/run",
            json={"scenario": "comment", "payload": VALID_COMMENT_PAYLOAD},
            headers=auth_headers,
        )
        expected = SQLLabService.run_scenario("comment", VALID_COMMENT_PAYLOAD)
        assert response.get_json()["data"] == expected


class TestSQLScenariosEndpoint:
    def test_without_jwt_returns_401(self, client):
        response = client.get("/api/sql/scenarios")
        assert response.status_code == 401
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "UNAUTHORIZED"

    def test_with_jwt_returns_200(self, client, auth_headers):
        response = client.get("/api/sql/scenarios", headers=auth_headers)
        assert response.status_code == 200

    def test_all_four_scenario_ids_returned(self, client, auth_headers):
        response = client.get("/api/sql/scenarios", headers=auth_headers)
        body = response.get_json()
        assert set(body["data"]) == {"login", "union", "boolean", "comment"}

    def test_scenario_entries_are_json_safe(self, client, auth_headers):
        response = client.get("/api/sql/scenarios", headers=auth_headers)
        body = response.get_json()
        assert body["success"] is True
        assert body["message"] == "SQL playground scenarios retrieved"
        for scenario_id, scenario in body["data"].items():
            assert scenario["id"] == scenario_id
            for field in (
                "name",
                "description",
                "example_payload",
                "vulnerable_explanation",
                "secure_explanation",
                "mitigation",
            ):
                assert isinstance(scenario[field], str) and scenario[field]

    def test_no_supabase_client_accessed_by_scenarios_route(
        self, client, auth_headers, fake_supabase
    ):
        response = client.get("/api/sql/scenarios", headers=auth_headers)
        assert response.status_code == 200
        assert fake_supabase.auth_tokens == []
        assert fake_supabase.inserts == {}
