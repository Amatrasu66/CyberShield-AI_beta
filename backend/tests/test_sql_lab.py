"""Tests for the isolated SQL Playground sandbox service (Phase 1).

Covers database isolation, all four educational scenarios, malicious payload
confinement, input validation, ephemerality/persistence, and the guarantee that
no sensitive information ever leaves the sandbox.
"""

import inspect
import re
import sqlite3
import tempfile

import pytest

from app.errors import ValidationError
from app.services import sql_lab_service
from app.services.sql_lab_service import (
    SCENARIOS,
    SQL_PAYLOAD_MAX_LENGTH,
    SQLLabService,
)

LOGIN_BYPASS = "' OR '1'='1"
UNION_PAYLOAD = "' UNION SELECT username, role FROM users --"
BOOLEAN_TRUE = "' AND 1=1 --"
BOOLEAN_FALSE = "' AND 1=2 --"
COMMENT_PAYLOAD = "admin'--"

# Expected deterministic seed counts.
USERS_TOTAL = 4
USERS_WITH_ROLE_USER = 3
PRODUCTS_TOTAL = 6

# The safe, generic rejection reasons the service is allowed to report. No
# sqlite3 message text, paths, or internal details may ever be forwarded.
SAFE_REJECTION_REASONS = {
    "multiple statements are not allowed",
    "blocked by the sandbox guard",
    "maximum query work exceeded",
    "SQL syntax was rejected",
    "the query could not be executed inside the sandbox",
}

MALICIOUS_PAYLOADS = [
    "'; DROP TABLE users; --",
    "' OR 1=1; DROP TABLE users; --",
    "x'; DROP TABLE products; --",
    "'; DROP TABLE orders; --",
    "; DROP TABLE users;",
    "' UNION SELECT username, role FROM users; DROP TABLE users; --",
    "'; SELECT 1; --",
    "'; SELECT sql FROM sqlite_master; --",
    "' UNION SELECT sql, 1 FROM sqlite_master --",
    "' UNION SELECT name, sql FROM sqlite_master --",
    "'; ATTACH DATABASE '/tmp/evil.db' AS evil; --",
    "'; ATTACH DATABASE 'C:/tmp/evil.db' AS evil; --",
    "'; DETACH DATABASE main; --",
    "'; PRAGMA journal_mode=WAL; --",
    "'; PRAGMA writable_schema=ON; --",
    "' AND 1=1; PRAGMA foreign_keys; --",
    "' OR 1=1; LOAD_EXTENSION('C:/x.dll'); --",
    "' UNION SELECT load_extension('/tmp/x.dll'), 1 --",
    "' AND load_extension('C:/x.dll') --",
    "' OR '1'='1' UNION SELECT username, role FROM users --",
    "x' OR 1=1 OR 'x'='x --",
    "../../../etc/passwd",
    "C:\\Windows\\system32\\config\\sam",
    "file:///etc/passwd",
    "postgres://user:pass@localhost/prod",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake.sig",
    "%00' OR 1=1 --",
]

FORBIDDEN_RESULT_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}", re.I),
    re.compile(r"password", re.I),
    re.compile(r"passwd", re.I),
    re.compile(r"api[_-]?key", re.I),
    re.compile(r"supabase", re.I),
    re.compile(r"postgres", re.I),
    re.compile(r"bearer\s+", re.I),
    re.compile(r"secret", re.I),
    re.compile(r"token", re.I),
    re.compile(r"[A-Za-z]:[\\/]"),
    re.compile(r"/etc/|/home/|/Users/|/tmp/", re.I),
    re.compile(r"://"),
    re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"),
    re.compile(r"operationalerror|programmingerror|databaseerror|integrityerror", re.I),
    re.compile(r"sqlite3|not authorized|traceback|inner|you can only execute", re.I),
]


def _walk_strings(result):
    """Collect every user-visible string from a run result (excluding the
    caller-controlled ``input``/query echo fields)."""
    collected = []

    def visit(value):
        if isinstance(value, str):
            collected.append(value)
        elif isinstance(value, (list, tuple)):
            for item in value:
                visit(item)
        elif isinstance(value, dict):
            for key, item in value.items():
                if key in ("input", "vulnerable_query", "safe_query"):
                    continue
                visit(item)

    visit(result)
    return collected


def _assert_contained(result, scenario_id):
    """Assert a well-formed, fully-contained result for any payload."""
    assert result["scenario"] == scenario_id
    assert result["vulnerable_result"]["execution_status"] in {"ok", "rejected"}
    assert result["safe_result"]["execution_status"] == "ok"
    assert result["vulnerable_result"]["rows"] == len(result["vulnerable_result"]["data"])
    assert result["safe_result"]["rows"] == len(result["safe_result"]["data"])
    reason = result["vulnerable_result"].get("rejection_reason")
    if reason is not None:
        assert reason in SAFE_REJECTION_REASONS, reason


# --------------------------------------------------------------------------- #
# Scenario catalog
# --------------------------------------------------------------------------- #


class TestScenarioCatalog:
    def test_fixed_catalog_exact(self):
        assert set(SCENARIOS) == {"login", "union", "boolean", "comment"}

    def test_each_scenario_has_required_fields(self):
        for sid, scenario in SCENARIOS.items():
            assert scenario["id"] == sid
            for field in (
                "name",
                "description",
                "example_payload",
                "vulnerable_template",
                "secure_template",
                "vulnerable_explanation",
                "secure_explanation",
                "mitigation",
            ):
                assert scenario[field], f"{sid}.{field} is empty"
            assert "{payload}" in scenario["vulnerable_template"]
            assert "?" in scenario["secure_template"]

    def test_available_scenarios_is_read_only(self):
        catalog = SQLLabService.available_scenarios()
        assert set(catalog) == set(SCENARIOS)
        catalog["login"]["id"] = "mutated"
        catalog["login"]["vulnerable_template"] = "SELECT 1"
        assert SCENARIOS["login"]["id"] == "login"
        assert "{payload}" in SCENARIOS["login"]["vulnerable_template"]

    def test_example_payloads_are_well_formed(self):
        for sid, scenario in SCENARIOS.items():
            result = SQLLabService.run_scenario(sid, scenario["example_payload"])
            assert result["scenario"] == sid
            _assert_contained(result, sid)


# --------------------------------------------------------------------------- #
# Login scenario
# --------------------------------------------------------------------------- #


class TestLoginScenario:
    def test_known_user_works_on_both_paths(self):
        result = SQLLabService.run_scenario("login", "alice")
        assert result["vulnerable_result"]["rows"] == 1
        assert result["safe_result"]["rows"] == 1
        assert result["vulnerable_result"]["data"][0][1] == "alice"
        assert result["safe_result"]["data"][0][1] == "alice"

    def test_classic_bypass_differs(self):
        result = SQLLabService.run_scenario("login", LOGIN_BYPASS)
        assert result["vulnerable_result"]["rows"] == USERS_WITH_ROLE_USER
        assert result["safe_result"]["rows"] == 0
        usernames = [row[1] for row in result["vulnerable_result"]["data"]]
        assert usernames == ["alice", "bob", "carol"]
        assert "admin" not in usernames
        assert result["vulnerable_result"]["columns"] == ["id", "username", "role"]

    def test_bypass_returns_no_password_material(self):
        result = SQLLabService.run_scenario("login", LOGIN_BYPASS)
        for section in ("vulnerable_result", "safe_result"):
            assert "password" not in result[section]["columns"]
            assert all("password" not in str(cell).lower() for row in result[section]["data"] for cell in row)

    def test_empty_payload_is_deterministic(self):
        result = SQLLabService.run_scenario("login", "")
        assert result["vulnerable_result"]["rows"] == 0
        assert result["safe_result"]["rows"] == 0
        assert result["vulnerable_result"]["execution_status"] == "ok"


# --------------------------------------------------------------------------- #
# Union scenario
# --------------------------------------------------------------------------- #


class TestUnionScenario:
    def test_union_extracts_users_on_vulnerable_path(self):
        result = SQLLabService.run_scenario("union", UNION_PAYLOAD)
        assert result["vulnerable_result"]["rows"] == USERS_TOTAL
        assert result["safe_result"]["rows"] == 0
        names = {row[0] for row in result["vulnerable_result"]["data"]}
        assert names == {"alice", "bob", "admin", "carol"}

    def test_union_without_comment_marker_still_works(self):
        # Balanced payload: the template's trailing quote closes the injected
        # string, so no comment marker is needed to keep the statement valid.
        result = SQLLabService.run_scenario("union", "' UNION SELECT username, role FROM users WHERE 'x'='x")
        assert result["vulnerable_result"]["rows"] == USERS_TOTAL
        assert result["safe_result"]["rows"] == 0

    def test_bind_treats_union_as_data(self):
        result = SQLLabService.run_scenario("union", UNION_PAYLOAD)
        assert result["safe_result"]["data"] == []
        assert result["safe_result"]["execution_status"] == "ok"


# --------------------------------------------------------------------------- #
# Boolean scenario
# --------------------------------------------------------------------------- #


class TestBooleanScenario:
    def test_true_payload_changes_result_set(self):
        result = SQLLabService.run_scenario("boolean", BOOLEAN_TRUE)
        assert result["vulnerable_result"]["rows"] == PRODUCTS_TOTAL
        assert result["safe_result"]["rows"] == 0

    def test_false_payload_changes_result_set(self):
        result = SQLLabService.run_scenario("boolean", BOOLEAN_FALSE)
        assert result["vulnerable_result"]["rows"] == 0
        assert result["safe_result"]["rows"] == 0

    def test_true_and_false_differ_on_vulnerable_path(self):
        true = SQLLabService.run_scenario("boolean", BOOLEAN_TRUE)
        false = SQLLabService.run_scenario("boolean", BOOLEAN_FALSE)
        assert true["vulnerable_result"]["rows"] != false["vulnerable_result"]["rows"]
        assert true["safe_result"]["rows"] == false["safe_result"]["rows"] == 0

    def test_secure_treats_payload_as_search_term(self):
        result = SQLLabService.run_scenario("boolean", "USB")
        assert result["vulnerable_result"]["rows"] == 1
        assert result["safe_result"]["rows"] == 1
        assert result["safe_result"]["data"][0][1] == "USB Drive"


# --------------------------------------------------------------------------- #
# Comment scenario
# --------------------------------------------------------------------------- #


class TestCommentScenario:
    def test_comment_truncates_role_filter(self):
        result = SQLLabService.run_scenario("comment", COMMENT_PAYLOAD)
        assert result["vulnerable_result"]["rows"] == 1
        assert result["vulnerable_result"]["data"][0][1:] == ["admin", "admin"]

    def test_secure_does_not_bypass(self):
        result = SQLLabService.run_scenario("comment", COMMENT_PAYLOAD)
        assert result["safe_result"]["rows"] == 0
        assert result["safe_result"]["data"] == []


# --------------------------------------------------------------------------- #
# Malicious payload confinement
# --------------------------------------------------------------------------- #


class TestMaliciousPayloads:
    @pytest.mark.parametrize("scenario_id", sorted(SCENARIOS))
    @pytest.mark.parametrize("payload", MALICIOUS_PAYLOADS)
    def test_payload_cannot_escape_its_scenario(self, scenario_id, payload):
        result = SQLLabService.run_scenario(scenario_id, payload)
        _assert_contained(result, scenario_id)
        # The executed SQL is always anchored to the fixed template prefix: a
        # payload can never supply a standalone statement.
        scenario = SCENARIOS[scenario_id]
        fixed_prefix = scenario["vulnerable_template"].split("{payload}")[0]
        assert result["vulnerable_query"].startswith(fixed_prefix)
        # The parameterized path always treats the payload as data.
        assert result["safe_result"]["rows"] == 0

    def test_authorizer_rejects_forbidden_operations(self):
        from app.services.sql_lab_service import _open_lab_database

        forbidden = [
            "ATTACH DATABASE ':memory:' AS other",
            "DETACH DATABASE other",
            "CREATE TABLE evil (id INTEGER)",
            "DROP TABLE users",
            "DELETE FROM users",
            "UPDATE users SET role = 'x'",
            "INSERT INTO users (id, username, role) VALUES (99, 'x', 'y')",
            "ALTER TABLE users ADD COLUMN x",
            "PRAGMA journal_mode=WAL",
            "SELECT * FROM sqlite_master",
        ]
        with _open_lab_database() as conn:
            for statement in forbidden:
                with pytest.raises(sqlite3.DatabaseError):
                    conn.execute(statement)

    def test_authorizer_allows_educational_queries(self):
        from app.services.sql_lab_service import _open_lab_database

        with _open_lab_database() as conn:
            assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == USERS_TOTAL
            assert conn.execute("SELECT COUNT(*) FROM products").fetchone()[0] == PRODUCTS_TOTAL
            assert conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0] == 5

    def test_no_arbitrary_sql_entry_point(self):
        assert not hasattr(SQLLabService, "run_sql")
        assert not hasattr(SQLLabService, "execute_query")
        assert not hasattr(SQLLabService, "execute")
        assert not hasattr(SQLLabService, "run_query")
        with pytest.raises(TypeError):
            SQLLabService.run_scenario("login", "x", query="SELECT 1")


# --------------------------------------------------------------------------- #
# Input validation
# --------------------------------------------------------------------------- #


class TestInputValidation:
    def test_missing_payload(self):
        with pytest.raises(ValidationError) as exc:
            SQLLabService.run_scenario("login", None)
        assert exc.value.status_code == 400

    def test_non_string_payload(self):
        for bad in (123, ["x"], {"x": 1}, b"bytes", 0.5, True):
            with pytest.raises(ValidationError):
                SQLLabService.run_scenario("login", bad)

    def test_empty_payload_runs(self):
        result = SQLLabService.run_scenario("login", "")
        assert result["scenario"] == "login"

    def test_payload_at_exact_limit(self):
        payload = "a" * SQL_PAYLOAD_MAX_LENGTH
        result = SQLLabService.run_scenario("login", payload)
        assert result["vulnerable_result"]["execution_status"] == "ok"
        assert result["vulnerable_result"]["rows"] == 0

    def test_payload_over_limit(self):
        with pytest.raises(ValidationError) as exc:
            SQLLabService.run_scenario("login", "a" * (SQL_PAYLOAD_MAX_LENGTH + 1))
        assert "maximum length" in str(exc.value)

    def test_custom_max_length(self):
        with pytest.raises(ValidationError):
            SQLLabService.run_scenario("login", "a" * 100, max_length=50)
        assert SQLLabService.run_scenario("login", "a" * 50, max_length=50)["scenario"] == "login"

    @pytest.mark.parametrize("bad_scenario", [None, "", "nope", "LOGIN", " login", 42, {"id": "login"}])
    def test_unknown_scenario(self, bad_scenario):
        with pytest.raises(ValidationError) as exc:
            SQLLabService.run_scenario(bad_scenario, "x")
        assert "Unknown SQL lab scenario" in str(exc.value)


# --------------------------------------------------------------------------- #
# Database isolation & ephemerality
# --------------------------------------------------------------------------- #


class TestDatabaseIsolation:
    def test_identical_results_across_runs(self):
        first = SQLLabService.run_scenario("union", UNION_PAYLOAD)
        second = SQLLabService.run_scenario("union", UNION_PAYLOAD)
        assert first == second

    def test_fresh_seed_after_destructive_payloads(self):
        for scenario_id in SCENARIOS:
            SQLLabService.run_scenario(scenario_id, "'; DROP TABLE users; --")
        result = SQLLabService.run_scenario("union", UNION_PAYLOAD)
        assert result["vulnerable_result"]["rows"] == USERS_TOTAL
        names = {row[0] for row in result["vulnerable_result"]["data"]}
        assert names == {"alice", "bob", "admin", "carol"}

    def test_no_cross_scenario_state(self):
        SQLLabService.run_scenario("boolean", BOOLEAN_TRUE)
        SQLLabService.run_scenario("comment", COMMENT_PAYLOAD)
        result = SQLLabService.run_scenario("boolean", BOOLEAN_TRUE)
        assert result["vulnerable_result"]["rows"] == PRODUCTS_TOTAL

    def test_only_memory_databases_are_opened(self, monkeypatch):
        opened = []
        real_connect = sqlite3.connect

        def fake_connect(*args, **kwargs):
            opened.append(args)
            return real_connect(*args, **kwargs)

        monkeypatch.setattr(sqlite3, "connect", fake_connect)
        for scenario_id in SCENARIOS:
            SQLLabService.run_scenario(scenario_id, "alice")
        assert opened
        assert all(args == (":memory:",) for args in opened)

    def test_module_never_touches_external_systems(self):
        source = inspect.getsource(sql_lab_service)
        assert "import supabase" not in source
        assert "import postgres" not in source
        assert "psycopg" not in source.lower()
        assert "from ..database" not in source
        assert "app.database" not in source
        assert ":memory:" in source
        assert "sqlite3.connect(" in source
        # No external subsystem is ever imported by the module.
        assert not any(name.lower().startswith("supabase") for name in vars(sql_lab_service))
        # No arbitrary-SQL entry point exists on the service.
        assert not hasattr(SQLLabService, "run_sql")
        assert not hasattr(SQLLabService, "execute_query")


class TestPersistence:
    def test_no_sqlite_files_written_anywhere(self):
        from pathlib import Path

        watch_dirs = [Path(tempfile.mkdtemp(prefix="sqllab_"))]
        backend_dir = Path(__file__).resolve().parent.parent
        after_suffixes = {".db", ".sqlite", ".sqlite3", ".db3"}

        for scenario_id in SCENARIOS:
            SQLLabService.run_scenario(scenario_id, MALICIOUS_PAYLOADS[0])

        for watch in watch_dirs:
            assert not [p for p in watch.rglob("*") if p.suffix.lower() in after_suffixes]
        assert not [p for p in backend_dir.rglob("*.db") if "venv" not in str(p)]
        assert not [p for p in backend_dir.rglob("*.sqlite*") if "venv" not in str(p)]

    def test_sandbox_marker_present(self):
        result = SQLLabService.run_scenario("login", LOGIN_BYPASS)
        assert result["sandbox"] == "in-memory sqlite (isolated, non-persistent)"


# --------------------------------------------------------------------------- #
# Sensitive information
# --------------------------------------------------------------------------- #


class TestSensitiveInformation:
    @pytest.mark.parametrize("scenario_id", sorted(SCENARIOS))
    @pytest.mark.parametrize("payload", [LOGIN_BYPASS, UNION_PAYLOAD, COMMENT_PAYLOAD, MALICIOUS_PAYLOADS[0]])
    def test_no_sensitive_material_in_results(self, scenario_id, payload):
        result = SQLLabService.run_scenario(scenario_id, payload)
        for text in _walk_strings(result):
            for pattern in FORBIDDEN_RESULT_PATTERNS:
                assert not pattern.search(text), f"forbidden pattern {pattern.pattern!r} in {text!r}"

    def test_every_scenario_reports_raw_payload_only_in_explicit_fields(self):
        for scenario_id in SCENARIOS:
            result = SQLLabService.run_scenario(scenario_id, MALICIOUS_PAYLOADS[0])
            raw = MALICIOUS_PAYLOADS[0]
            assert result["input"] == raw
            assert result["vulnerable_query"] != raw  # anchored to the fixed template

    def test_result_structure(self):
        result = SQLLabService.run_scenario("login", LOGIN_BYPASS)
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
            assert key in result
        for key in ("rows", "columns", "data", "execution_status"):
            assert key in result["vulnerable_result"]
            assert key in result["safe_result"]
        for key in ("what_happened", "why_vulnerable", "why_safe", "mitigation"):
            assert result["explanation"][key]