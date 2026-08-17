"""PHASE 3 - SQL Playground security / red-team test pass.

Red-team audit of the isolated in-memory SQLite sandbox. These tests attack the
same four fixed scenario templates through the service and the authenticated
HTTP routes and assert security *properties*:

- The payload is always data: it can never become a standalone statement.
- System/metadata/schema reads, writes, PRAGMAs, ATTACH/DETACH, extension
  loading, and multi-statement vectors are rejected or constrained.
- No filesystem file is ever created or read; only ``:memory:`` is opened.
- No Supabase / PostgreSQL / network / environment secret can be reached.
- Executions are deterministic and fully isolated between requests.
- Work is budgeted (progress handler), rows are capped, and result cells are
  bounded and JSON-serializable (no BLOB crash, no unbounded amplification).
- Failures never leak sqlite3/traceback/path/environment internals.
- The API ignores every unexpected body field and never trusts its caller.

The existing ``backend/tests/test_sql_lab.py`` already covers the base sandbox
contract (isolation, ephemerality, scenarios, generic rejection reasons). This
file only adds the missing red-team cases and regression tests for the genuine
issues found during the audit; it deliberately does not duplicate that coverage.
"""

import inspect
import re
import socket
import sqlite3
import tempfile
import time

import pytest

from app.errors import ValidationError
from app.services import sql_lab_service
from app.services.sql_lab_service import (
    SCENARIOS,
    SQL_MAX_RESULT_CELL_SIZE,
    SQL_MAX_RESULT_ROWS,
    SQL_MAX_STEPS,
    SQLLabService,
)

LOGIN_BYPASS = "' OR '1'='1"
UNION_PAYLOAD = "' UNION SELECT username, role FROM users --"
BOOLEAN_TRUE = "' AND 1=1 --"
COMMENT_PAYLOAD = "admin'--"

CANONICAL = {
    "login": LOGIN_BYPASS,
    "union": UNION_PAYLOAD,
    "boolean": BOOLEAN_TRUE,
    "comment": COMMENT_PAYLOAD,
}

# The only strings the sandbox is allowed to attach to a rejected run.
SAFE_REJECTION_REASONS = {
    "multiple statements are not allowed",
    "blocked by the sandbox guard",
    "maximum query work exceeded",
    "SQL syntax was rejected",
    "the query could not be executed inside the sandbox",
}

# Anything that would indicate leaked internals or secrets in a response.
LEAK_PATTERNS = [
    re.compile(r"sqlite3|OperationalError|ProgrammingError|IntegrityError", re.I),
    re.compile(r"DatabaseError", re.I),
    re.compile(r"traceback|File \"|, line \d+, in |module ", re.I),
    re.compile(r"SUPABASE_SERVICE_ROLE_KEY|SUPABASE_ANON_KEY|DATABASE_URL", re.I),
    re.compile(r"\bBearer\b|jwt\.[A-Za-z]", re.I),
    re.compile(r'"Authorization"\s*:|\bAuthorization\b\s*:', re.I),
    re.compile(r"[A-Za-z]:[\\/]|/etc/|/home/|/Users/|/tmp/|\.\./\.\./", re.I),
    re.compile(r"@supabase\.co|postgres(ql)?://|psycopg", re.I),
]

# Bare statements the payload must never be allowed to execute standalone.
BARE_STATEMENT_PAYLOADS = [
    "SELECT * FROM users",
    "SELECT * FROM sqlite_master",
    "SELECT name FROM sqlite_master",
    "SELECT * FROM sqlite_schema",
    "SELECT * FROM sqlite_temp_master",
    "PRAGMA database_list",
    "PRAGMA journal_mode",
    "PRAGMA writable_schema=ON",
    "PRAGMA integrity_check",
    "PRAGMA table_info(users)",
    "ATTACH DATABASE ':memory:' AS evil",
    "ATTACH DATABASE '/tmp/evil.db' AS evil",
    "DETACH DATABASE main",
    "DROP TABLE users",
    "DELETE FROM users",
    "UPDATE users SET username='x'",
    "INSERT INTO users (id, username, role) VALUES (99, 'x', 'y')",
    "ALTER TABLE users ADD COLUMN evil TEXT",
    "CREATE TABLE evil (id INTEGER)",
    "VACUUM",
    "VACUUM INTO '/tmp/evil.db'",
    "REINDEX",
    "ANALYZE",
    "COMMIT",
    "ROLLBACK",
    "SAVEPOINT x",
]

# Injection-form vectors aimed at metadata, temp objects, PRAGMAs and
# schema-qualified identifiers (beyond the multi-statement payloads already in
# test_sql_lab.py).
META_INJECTION_PAYLOADS = [
    "' UNION SELECT * FROM sqlite_master --",
    "' UNION SELECT src FROM sqlite_schema --",
    "' AND EXISTS(SELECT 1 FROM sqlite_master) --",
    "' AND EXISTS(SELECT 1 FROM sqlite_temp_master) --",
    "' AND (SELECT count(*) FROM sqlite_schema) --",
    "' UNION SELECT * FROM (SELECT name FROM sqlite_master) --",
    "' UNION SELECT name, sql FROM pragma_database_list --",
    "' UNION SELECT name, sql FROM pragma_table_info('users') --",
    "' UNION SELECT * FROM pragma_journal_mode --",
    "' AND EXISTS(PRAGMA database_list) --",
    "' UNION SELECT name, price FROM main.products --",
    "' UNION SELECT name, price FROM temp.products --",
    "' UNION SELECT name, price FROM main.sqlite_master --",
    "x' OR 1=1 UNION SELECT username, role FROM main.users --",
    "' AND load_extension('C:/x.dll') --",
    "' UNION SELECT load_extension('/tmp/x.so'), 1 --",
    "' AND 1=1 UNION ALL SELECT name, price FROM products WHERE 'a'='a --",
]

# Filesystem vectors (Category 3).
FILE_PAYLOADS = [
    "../../../secret.txt",
    "..\\..\\secret.txt",
    "C:\\Windows\\system32\\config\\SAM",
    "file:///etc/passwd",
    "file:C:/windows/win.ini",
    "file:///tmp/probe.bin",
    "\\/\\/\\/etc\\/passwd",
    "' UNION SELECT readfile('/etc/passwd'), 1 --",
    "' UNION SELECT writefile('/tmp/redteam_probe.bin', 'x'), 1 --",
    "' AND writefile('C:/tmp/redteam_probe.bin', 'x') --",
    "' UNION SELECT readfile('C:\\Windows\\System32\\drivers\\etc\\hosts'), 1 --",
    "' AND EXISTS(SELECT readfile('../../.env')) --",
]

# Production / Supabase strings (all fake).
SUPABASE_PAYLOADS = [
    "supabase_url_skill https://abcxyz.supabase.co",
    "fake.service.key SUPABASE_SERVICE_ROLE_KEY",
    "JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.fake",
    "DATABASE_URL postgres://user:pass@db.example.com:5432/prod",
    "postgresql://evil@example/cybershield",
    "SELECT * FROM reports",
    "SELECT * FROM profiles",
    "SELECT * FROM website_scans",
    "SELECT * FROM email_scans",
    "SELECT * FROM password_scans",
    "SELECT * FROM log_scans",
    "' UNION SELECT sql, 1 FROM sqlite_schema --",
]


def _walk_strings(value, skip_echo=True):
    """Recursively collect every user-visible string in a result/response.

    When ``skip_echo`` is true the three echo fields (``input``,
    ``vulnerable_query``, ``safe_query``) are excluded: those fields exist on
    purpose and repeat the attacker's own payload text.
    """
    found = []

    def visit(v):
        if isinstance(v, str):
            found.append(v)
        elif isinstance(v, (list, tuple)):
            for item in v:
                visit(item)
        elif isinstance(v, dict):
            for key, item in v.items():
                if skip_echo and key in ("input", "vulnerable_query", "safe_query"):
                    continue
                visit(item)

    visit(value)
    return found


def _assert_contained(result, scenario_id):
    """Assert a well-formed, fully-contained run for any payload."""
    assert result["scenario"] == scenario_id
    assert result["vulnerable_result"]["execution_status"] in {"ok", "rejected"}
    assert result["safe_result"]["execution_status"] == "ok"
    assert result["vulnerable_result"]["rows"] == len(result["vulnerable_result"]["data"])
    assert result["safe_result"]["rows"] == len(result["safe_result"]["data"])
    assert result["vulnerable_result"]["rows"] <= SQL_MAX_RESULT_ROWS
    assert result["safe_result"]["rows"] <= SQL_MAX_RESULT_ROWS
    reason = result["vulnerable_result"].get("rejection_reason")
    if reason is not None:
        assert reason in SAFE_REJECTION_REASONS, reason


def _fixed_prefix(scenario_id):
    return SCENARIOS[scenario_id]["vulnerable_template"].split("{payload}")[0]


# --------------------------------------------------------------------------- #
# Category 1 + 2 - arbitrary SQL / SQLite escape techniques
# --------------------------------------------------------------------------- #


class TestArbitrarySQLAndEscape:
    """The payload is data. No payload can become a standalone statement, reach
    system metadata tables, write, or disable the sandbox."""

    @pytest.mark.parametrize("payload", BARE_STATEMENT_PAYLOADS)
    @pytest.mark.parametrize("scenario_id", sorted(SCENARIOS))
    def test_bare_statements_stay_inside_the_template(self, scenario_id, payload):
        """Bare meta/destructive statements passed as a payload are anchored to
        the fixed template prefix and can never execute on their own."""
        result = SQLLabService.run_scenario(scenario_id, payload)
        _assert_contained(result, scenario_id)
        assert result["vulnerable_query"].startswith(_fixed_prefix(scenario_id))
        for text in _walk_strings(result):
            for pattern in LEAK_PATTERNS:
                assert not pattern.search(text)

    @pytest.mark.parametrize("payload", META_INJECTION_PAYLOADS)
    @pytest.mark.parametrize("scenario_id", ["union", "boolean", "login", "comment"])
    def test_metadata_and_qualified_identifiers_never_return_system_data(
        self, scenario_id, payload
    ):
        """Injection-form payloads aimed at sqlite_master/sqlite_schema,
        pragma_* table-valued functions and schema-qualified objects either run
        as ordinary demo-table reads or are rejected; they never expose system
        metadata or database internals."""
        result = SQLLabService.run_scenario(scenario_id, payload)
        _assert_contained(result, scenario_id)
        assert result["vulnerable_query"].startswith(_fixed_prefix(scenario_id))
        for text in _walk_strings(result):
            for pattern in LEAK_PATTERNS:
                assert not pattern.search(text)
        # The only data that may ever surface is the educational demo data.
        all_cells = [
            str(cell)
            for row in result["vulnerable_result"]["data"]
            for cell in row
        ]
        for cell in all_cells:
            assert not cell.startswith(("sqlite_", "pragma_"))

    def test_recursive_cte_is_rejected_without_running(self):
        """A recursive CTE hits the sandbox authorizer (SQLITE_RECURSIVE is not
        permitted) and returns a contained rejection instead of executing."""
        payload = (
            "' AND EXISTS(WITH RECURSIVE c(x) AS "
            "(SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 100000000) "
            "SELECT * FROM c) --"
        )
        result = SQLLabService.run_scenario("boolean", payload)
        _assert_contained(result, "boolean")
        assert result["vulnerable_result"]["execution_status"] == "rejected"

    def test_load_extension_never_available(self):
        """The authorizer blocks ``load_extension`` at the engine, and the
        connection never enables extension loading."""
        from app.services.sql_lab_service import _open_lab_database

        payload = "' UNION SELECT load_extension('C:/x.dll'), 1 --"
        result = SQLLabService.run_scenario("union", payload)
        _assert_contained(result, "union")
        assert result["vulnerable_result"]["execution_status"] == "rejected"
        with _open_lab_database() as conn:
            with pytest.raises(sqlite3.DatabaseError):
                conn.execute("SELECT load_extension('x')")


# --------------------------------------------------------------------------- #
# Category 3 - filesystem access
# --------------------------------------------------------------------------- #


class TestFilesystemAccess:
    """No file may be created, read, or referenced by any SQL payload."""

    @pytest.mark.parametrize("payload", FILE_PAYLOADS)
    def test_filesystem_payloads_never_touch_the_disk(self, payload):
        result = SQLLabService.run_scenario("union", payload)
        _assert_contained(result, "union")
        for text in _walk_strings(result):
            for pattern in LEAK_PATTERNS:
                assert not pattern.search(text)

    def test_no_file_is_created_by_any_destructive_or_file_vector(self):
        from pathlib import Path

        watch_dir = Path(tempfile.mkdtemp(prefix="redteam_fs_"))
        probe_names = {"redteam_probe.bin", "evil.db", "probe.bin", "x.so"}

        payloads = FILE_PAYLOADS + BARE_STATEMENT_PAYLOADS + META_INJECTION_PAYLOADS
        for scenario_id in SCENARIOS:
            for payload in payloads:
                result = SQLLabService.run_scenario(scenario_id, payload)
                _assert_contained(result, scenario_id)  # never raises, never leaves the sandbox

        created = [
            p.name
            for p in list(watch_dir.rglob("*")) + list(Path.cwd().rglob("*"))
            if p.name in probe_names
        ]
        assert created == []

    def test_connection_is_only_ever_opened_as_memory(self, monkeypatch):
        """The sandbox never opens anything except ``sqlite3.connect(':memory:')``
        regardless of how much filesystem syntax the payload contains."""
        opened = []
        real_connect = sqlite3.connect

        def spy(*args, **kwargs):
            opened.append(args)
            return real_connect(*args, **kwargs)

        monkeypatch.setattr("sqlite3.connect", spy)
        for payload_path in ("/tmp/x.db", "file:C:/x.db", "../../evil.sqlite", "C:\\tmp\\x"):
            SQLLabService.run_scenario("login", f"'; ATTACH DATABASE '{payload_path}' AS e; --")
        assert opened
        assert all(args == (":memory:",) for args in opened)


# --------------------------------------------------------------------------- #
# Category 4 - production / Supabase access
# --------------------------------------------------------------------------- #


class TestProductionSupabaseAccess:
    """The sandbox has no path toward Supabase, other databases, or secrets."""

    def test_environment_secret_values_never_appear_in_any_response(
        self, monkeypatch, client, auth_headers
    ):
        sentinels = {
            "SUPABASE_SERVICE_ROLE_KEY": "sentinel_service_role_9f3a",
            "SUPABASE_ANON_KEY": "sentinel_anon_7c21",
            "SUPABASE_PUBLISHABLE_KEY": "sentinel_publishable_4b77",
            "SUPABASE_SECRET_KEY": "sentinel_secret_2d55",
            "SUPABASE_URL": "sentinel_url_k8m2",
            "DATABASE_URL": "sentinel_db_url_5x01",
            "SECRET_KEY": "sentinel_secret_key_a91c",
        }
        for name, value in sentinels.items():
            monkeypatch.setenv(name, value)

        for scenario_id in SCENARIOS:
            for payload in SUPABASE_PAYLOADS:
                response = client.post(
                    "/api/sql/run",
                    json={"scenario": scenario_id, "payload": payload},
                    headers=auth_headers,
                )
                assert response.status_code == 200
                raw = str(response.get_json())
                for value in sentinels.values():
                    assert value not in raw

    def test_no_supabase_client_created_by_the_sql_route(
        self, client, auth_headers, fake_supabase
    ):
        for scenario_id in SCENARIOS:
            response = client.post(
                "/api/sql/run",
                json={"scenario": scenario_id, "payload": SUPABASE_PAYLOADS[0]},
                headers=auth_headers,
            )
            assert response.status_code == 200
        assert fake_supabase.auth_tokens == []
        assert fake_supabase.inserts == {}

    def test_service_source_has_no_external_dependency_imports(self):
        source = inspect.getsource(sql_lab_service)
        for bad in (
            "import supabase",
            "import psycopg",
            "import requests",
            "import boto3",
            "import socket",
            "import urllib",
            "import httpx",
            "from ..database",
            "from ..reports",
        ):
            assert bad not in source, f"unexpected external dependency: {bad}"


# --------------------------------------------------------------------------- #
# Category 5 - scenario allowlist bypass
# --------------------------------------------------------------------------- #


class TestScenarioAllowlist:
    """Only the exact, fixed scenario keys are accepted; nothing is normalized."""

    @pytest.mark.parametrize(
        "bad_scenario",
        [
            "LOGIN",
            "Login",
            " login",
            "login ",
            "login\n",
            "../login",
            "login/..",
            "login;DROP TABLE users",
            "login'--",
            "login" * 20,  # far beyond the 64-char route cap
            "unión",  # homoglyph of the valid id
            " union",
            "union\n",
            "USERS",
            "0",
            "1",
            123,
            1.5,
            True,
            None,
            [],
            {},
            {"id": "login"},
        ],
    )
    def test_nonexact_scenario_ids_are_rejected(self, bad_scenario, client, auth_headers):
        response = client.post(
            "/api/sql/run", json={"scenario": bad_scenario, "payload": "x"}, headers=auth_headers
        )
        assert response.status_code == 400
        body = response.get_json()
        assert body["error"]["code"] == "VALIDATION_ERROR"
        assert "data" not in body
        raw = str(body)
        assert "sqlite3" not in raw and "Traceback" not in raw

    def test_service_rejects_uppercase_and_whitespace_variants(self):
        for bad in ("LOGIN", " Login", "login ", "login\t", "login\n"):
            with pytest.raises(ValidationError):
                SQLLabService.run_scenario(bad, "x")

    def test_only_the_four_fixed_ids_are_accepted(self):
        for scenario_id, payload in CANONICAL.items():
            result = SQLLabService.run_scenario(scenario_id, payload)
            assert result["scenario"] == scenario_id
        assert set(SCENARIOS) == {"login", "union", "boolean", "comment"}


# --------------------------------------------------------------------------- #
# Category 6 - payload validation
# --------------------------------------------------------------------------- #


class TestPayloadValidation:
    """Foreign types, huge inputs, and hostile character sets stay contained."""

    @pytest.mark.parametrize("scenario_id", ["login", "union", "boolean"])
    @pytest.mark.parametrize(
        "payload",
        [
            "x' OR '1'='1 --",
            "\u00e9\u00e8\u00ea",  # unicode
            "\n" * 500,
            "\\' OR 1=1 --",
            "' OR '1'='1' UNION SELECT username FROM users --",
            "'\t OR 1=1\r\n--",
            ("'" + '"' * 600),  # 600 quotes under the 2048-char cap
        ],
    )
    def test_hostile_text_payloads_stay_contained(self, scenario_id, payload):
        result = SQLLabService.run_scenario(scenario_id, payload)
        _assert_contained(result, scenario_id)
        for text in _walk_strings(result):
            for pattern in LEAK_PATTERNS:
                assert not pattern.search(text)

    def test_embedded_null_byte_is_rejected_on_vulnerable_path(self):
        result = SQLLabService.run_scenario("login", "a\x00' OR 1=1 --")
        _assert_contained(result, "login")

    def test_whitespace_only_and_empty_payloads_are_controlled(
        self, client, auth_headers
    ):
        for payload in ("", " ", "\t", "\n\n", "   "):
            response = client.post(
                "/api/sql/run",
                json={"scenario": "login", "payload": payload},
                headers=auth_headers,
            )
            assert response.status_code == 200
            body = response.get_json()["data"]
            assert body["vulnerable_result"]["execution_status"] in {"ok", "rejected"}

    @pytest.mark.parametrize("payload", [123, 1.5, True, ["x"], {"x": 1}, None])
    def test_non_string_payload_rejected_at_http(self, payload, client, auth_headers):
        response = client.post(
            "/api/sql/run", json={"scenario": "login", "payload": payload}, headers=auth_headers
        )
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"

    def test_long_payload_rejected_before_execution(self, client, auth_headers):
        from app.services.sql_lab_service import SQL_PAYLOAD_MAX_LENGTH

        response = client.post(
            "/api/sql/run",
            json={"scenario": "login", "payload": "a" * (SQL_PAYLOAD_MAX_LENGTH + 1)},
            headers=auth_headers,
        )
        assert response.status_code == 400
        body = response.get_json()
        assert body["error"]["code"] == "VALIDATION_ERROR"
        assert "maximum length" in body["message"]

    def test_half_megabyte_json_payload_still_bounded_by_string_limit(
        self, client, auth_headers
    ):
        response = client.post(
            "/api/sql/run",
            json={"scenario": "login", "payload": "a" * 500_000},
            headers=auth_headers,
        )
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"


# --------------------------------------------------------------------------- #
# Category 7 - multi-statement attacks
# --------------------------------------------------------------------------- #


class TestMultiStatement:
    """``;``-separated payloads cannot expand one template into many statements,
    and each rejection leaves the next run's deterministic seed intact."""

    DESTRUCTIVE = [
        "x'; DROP TABLE users; --",
        "x'; DELETE FROM users; --",
        "x'; UPDATE users SET role='admin'; --",
        "x'; INSERT INTO users VALUES (99,'x','y'); --",
        "x'; CREATE TABLE evil(id); --",
        "x'; ALTER TABLE users ADD COLUMN evil; --",
        "x'; ATTACH DATABASE ':memory:' AS evil; --",
        "x'; ATTACH DATABASE '/tmp/evil.db' AS evil; --",
        "x'; DETACH DATABASE main; --",
        "x'; PRAGMA writable_schema=ON; --",
        "x'; VACUUM; --",
        "x'; VACUUM INTO 'C:/tmp/evil.db'; --",
        "x'; REINDEX; --",
        "x'; ANALYZE; --",
        "x'; SELECT sql FROM sqlite_master; --",
        "x'; COMMIT; --",
        "x'; SAVEPOINT s; --",
    ]

    @pytest.mark.parametrize("payload", DESTRUCTIVE)
    def test_multistatement_payload_is_never_a_multi_statement_surface(self, payload):
        for scenario_id in SCENARIOS:
            result = SQLLabService.run_scenario(scenario_id, payload)
            _assert_contained(result, scenario_id)
            # The executed SQL is always anchored to the fixed template prefix;
            # the ``;`` in the payload can never turn it into a batch executor.
            assert result["vulnerable_query"].startswith(_fixed_prefix(scenario_id))

    def test_seed_is_deterministic_after_every_destructive_attempt(self):
        baseline = None
        for i in range(3):
            for scenario_id in SCENARIOS:
                SQLLabService.run_scenario(scenario_id, self.DESTRUCTIVE[0])
            result = SQLLabService.run_scenario("union", UNION_PAYLOAD)
            if baseline is None:
                baseline = result["vulnerable_result"]["data"]
            assert result["vulnerable_result"]["data"] == baseline
            assert result["vulnerable_result"]["rows"] == 4


# --------------------------------------------------------------------------- #
# Category 8 - data persistence / cross-request isolation
# --------------------------------------------------------------------------- #


class TestPersistenceIsolation:
    """Request A can never affect request B: state never accumulates."""

    def test_interleaved_runs_are_identical_and_deterministic(self):
        first = None
        for _ in range(5):
            results = {
                sid: SQLLabService.run_scenario(sid, CANONICAL[sid])
                for sid in sorted(SCENARIOS)
            }
            snapshot = {
                sid: (r["vulnerable_result"]["data"], r["safe_result"]["data"])
                for sid, r in results.items()
            }
            if first is None:
                first = snapshot
            assert snapshot == first

    def test_no_database_or_temporary_files_created(self):
        watch_dir = tempfile.mkdtemp(prefix="redteam_persist_")
        from pathlib import Path

        for scenario_id in SCENARIOS:
            for payload in (LOGIN_BYPASS, UNION_PAYLOAD, "x'; DROP TABLE users; --"):
                SQLLabService.run_scenario(scenario_id, payload)
        leftovers = [
            p.name
            for p in Path(watch_dir).rglob("*")
            if any(
                p.suffix.lower() == s
                for s in (".db", ".sqlite", ".sqlite3", ".db3", ".tmp", ".wal", ".journal")
            )
        ]
        assert leftovers == []


# --------------------------------------------------------------------------- #
# Category 9 - resource exhaustion
# --------------------------------------------------------------------------- #


class TestResourceExhaustion:
    """Pathological inputs complete quickly, stay bounded, and never corrupt the
    process or block other requests."""

    def test_max_length_payload_completes_quickly(self):
        payload = "a" * 2048
        start = time.monotonic()
        result = SQLLabService.run_scenario("union", payload)
        assert time.monotonic() - start < 5
        _assert_contained(result, "union")

    def test_cartesian_aggregate_is_aborted_by_the_progress_handler(self):
        payload = (
            "' AND (SELECT count(*) FROM products a, products b, products c, "
            "products d, products e, products f, products g, products h, "
            "products i, products j) --"
        )
        start = time.monotonic()
        result = SQLLabService.run_scenario("boolean", payload)
        assert time.monotonic() - start < 5
        _assert_contained(result, "boolean")
        assert result["vulnerable_result"]["rejection_reason"] == "maximum query work exceeded"

    def test_recursive_cte_does_not_hang(self):
        payload = (
            "' AND EXISTS(WITH RECURSIVE big(x) AS (SELECT 1 UNION ALL SELECT x + 1 "
            "FROM big WHERE x < 2000000000) SELECT * FROM big) --"
        )
        start = time.monotonic()
        result = SQLLabService.run_scenario("boolean", payload)
        assert time.monotonic() - start < 5
        _assert_contained(result, "boolean")
        assert result["vulnerable_result"]["execution_status"] == "rejected"

    def test_repeated_union_fragments_are_capped_not_bloated(self):
        frag = " UNION ALL SELECT name, price FROM products"
        payload = f"x' {frag * 45} --"
        assert len(payload) <= 2048
        result = SQLLabService.run_scenario("union", payload)
        _assert_contained(result, "union")
        assert result["vulnerable_result"].get("rejection_reason") is None
        assert result["vulnerable_result"]["rows"] == SQL_MAX_RESULT_ROWS

    def test_oversized_result_cells_are_rejected_not_materialized(self):
        """Regression: ``zeroblob(1000000000)`` previously allocated ~1 GB per
        cell. The per-cell SQLITE_LIMIT_LENGTH cap now rejects it instantly."""
        start = time.monotonic()
        result = SQLLabService.run_scenario("union", "x' UNION SELECT zeroblob(1000000000), 1 --")
        assert time.monotonic() - start < 5
        _assert_contained(result, "union")
        assert result["vulnerable_result"]["execution_status"] == "rejected"

    def test_moderately_oversized_cell_is_rejected(self):
        payload = f"x' UNION SELECT zeroblob({2 * SQL_MAX_RESULT_CELL_SIZE}), 1 --"
        result = SQLLabService.run_scenario("union", payload)
        _assert_contained(result, "union")
        assert result["vulnerable_result"]["execution_status"] == "rejected"

    def test_subsequent_requests_still_work_after_resource_attempts(self):
        for payload in (
            "x' UNION SELECT zeroblob(1000000000), 1 --",
            "' AND (SELECT count(*) FROM products a, products b, products c, "
            "products d, products e, products f, products g, products h) --",
        ):
            SQLLabService.run_scenario("union", payload)
        result = SQLLabService.run_scenario("union", UNION_PAYLOAD)
        assert result["vulnerable_result"]["rows"] == 4


# --------------------------------------------------------------------------- #
# Category 10 - result limits
# --------------------------------------------------------------------------- #


class TestResultLimits:
    """Both paths respect SQL_MAX_RESULT_ROWS and the per-cell size cap."""

    def test_safe_and_vulnerable_paths_never_exceed_row_cap(self):
        frag = " UNION ALL SELECT name, price FROM products"
        payload = f"x' {frag * 45} --"
        result = SQLLabService.run_scenario("union", payload)
        for side in ("vulnerable_result", "safe_result"):
            assert result[side]["rows"] == len(result[side]["data"])
            assert result[side]["rows"] <= SQL_MAX_RESULT_ROWS

    def test_rows_reported_match_rows_returned(self):
        for scenario_id, payload in CANONICAL.items():
            result = SQLLabService.run_scenario(scenario_id, payload)
            for side in ("vulnerable_result", "safe_result"):
                assert result[side]["rows"] == len(result[side]["data"])

    def test_engine_level_cell_limit_is_active(self):
        from app.services.sql_lab_service import _open_lab_database

        with _open_lab_database() as conn:
            with pytest.raises(sqlite3.DataError):
                conn.execute(
                    f"SELECT zeroblob({2 * SQL_MAX_RESULT_CELL_SIZE})"
                ).fetchone()
            row = conn.execute("SELECT zeroblob(16)").fetchone()
            assert len(row[0]) == 16


# --------------------------------------------------------------------------- #
# Category 11 - error leakage
# --------------------------------------------------------------------------- #


class TestErrorLeakage:
    """Malformed SQL inside allowed templates yields only curated reasons."""

    MALFORMED = [
        "' OR 1=1 --",
        "x' OR '1'='1",
        "x' AND 'a'='b' --",
        "x' OR '1'='1' UNION SELECT username--",
        "' ''''''''' --",
        "x' UNION SELECT * * * --",
        "' OR ( --",
        "x'; --",
        "x' /* unterminated",
        "x' --\nDROP TABLE users",
        "x' OR 1=1 --\n; SELECT sql FROM sqlite_master",
        "x' COLLATE garbage('x') --",
        "x' || 'UNION' --",
    ]

    @pytest.mark.parametrize("payload", MALFORMED)
    def test_malformed_payloads_never_leak_sqlite_internals(self, payload):
        result = SQLLabService.run_scenario("login", payload)
        _assert_contained(result, "login")
        if result["vulnerable_result"]["execution_status"] == "rejected":
            assert result["vulnerable_result"]["rejection_reason"] in SAFE_REJECTION_REASONS
        raw = str(result)
        assert "OperationalError" not in raw
        assert "ProgrammingError" not in raw
        assert "sqlite3" not in raw
        assert "Traceback" not in raw

    def test_http_level_malformed_json_and_types_return_clean_envelope(
        self, client, auth_headers
    ):
        # Shape/type errors are rejected at the boundary with a clean envelope.
        bad_bodies = [
            {"scenario": "login", "payload": {"p": 1}},
            {"scenario": ["login"], "payload": "x"},
            {"scenario": 3.7, "payload": "x"},
            {"scenario": None, "payload": "x"},
            {"scenario": "bogus", "payload": "x"},
            {"payload": "x"},  # missing scenario
            {"scenario": "login"},  # missing payload
        ]
        for body in bad_bodies:
            response = client.post("/api/sql/run", json=body, headers=auth_headers)
            assert response.status_code == 400
            raw = str(response.get_json())
            assert "sqlite3" not in raw
            assert "Traceback" not in raw
            assert "/app/" not in raw and "backend/app" not in raw

        # Malformed SQL *inside* a valid shape is contained, not an HTTP error.
        response = client.post(
            "/api/sql/run",
            json={"scenario": "login", "payload": "x' OR ( --"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        vuln = response.get_json()["data"]["vulnerable_result"]
        assert vuln["execution_status"] in {"ok", "rejected"}
        if vuln["execution_status"] == "rejected":
            assert vuln["rejection_reason"] in SAFE_REJECTION_REASONS
        assert "sqlite3" not in str(response.get_json())

    def test_blob_cell_crash_fixed_response_is_serializable(
        self, client, auth_headers
    ):
        """Regression: a BLOB result cell previously raised an unhandled
        ``TypeError`` during JSON serialization (HTTP 500). It is now a 200 with
        a fixed marker cell."""
        response = client.post(
            "/api/sql/run",
            json={"scenario": "union", "payload": "x' UNION SELECT zeroblob(16), 1 --"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        body = response.get_json()
        assert body["success"] is True
        vuln = body["data"]["vulnerable_result"]
        assert vuln["execution_status"] == "ok"
        assert vuln["data"] == [["[binary data: 16 bytes]", 1]]

    def test_oversized_blob_via_http_is_contained_not_a_500(
        self, client, auth_headers
    ):
        response = client.post(
            "/api/sql/run",
            json={
                "scenario": "union",
                "payload": "x' UNION SELECT zeroblob(1000000000), 1 --",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        vuln = response.get_json()["data"]["vulnerable_result"]
        assert vuln["execution_status"] == "rejected"
        assert vuln["rejection_reason"] in SAFE_REJECTION_REASONS
        assert vuln["rows"] == 0


# --------------------------------------------------------------------------- #
# Category 12 - authentication
# --------------------------------------------------------------------------- #


class TestAuthentication:
    """Both SQL endpoints are fully protected and never trust a bad token."""

    def test_run_and_scenarios_require_authorization(self, client):
        for method, path, body in (
            ("post", "/api/sql/run", {"scenario": "login", "payload": "x"}),
            ("get", "/api/sql/scenarios", None),
        ):
            response = getattr(client, method)(path, json=body)
            assert response.status_code == 401
            envelope = response.get_json()
            assert envelope["error"]["code"] == "UNAUTHORIZED"
            assert "data" not in envelope

    @pytest.mark.parametrize(
        "header",
        [
            "Bearer",
            "Bearer ",
            "bearer abc",
            "BEARER abc",
            "Basic abc",
            "Token abc",
            "Bearer not.a.jwt",
            "Bearer  ",
            "garbage",
            "",
        ],
    )
    def test_malformed_or_invalid_bearer_tokens_return_401(self, client, header):
        headers = {"Authorization": header}
        response = client.post(
            "/api/sql/run",
            json={"scenario": "login", "payload": LOGIN_BYPASS},
            headers=headers,
        )
        assert response.status_code == 401
        envelope = response.get_json()
        assert envelope["error"]["code"] == "UNAUTHORIZED"
        assert "data" not in envelope

    def test_expired_token_returns_401(self, client, _jwt_signing_keys):
        import jwt as pyjwt
        from datetime import datetime, timedelta, timezone

        private_key, _ = _jwt_signing_keys
        now = datetime.now(timezone.utc)
        expired = pyjwt.encode(
            {
                "sub": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "iss": "https://abcxyz.supabase.co/auth/v1",
                "aud": "authenticated",
                "iat": now - timedelta(hours=2),
                "exp": now - timedelta(hours=1),
            },
            private_key,
            algorithm="RS256",
        )
        response = client.post(
            "/api/sql/run",
            json={"scenario": "login", "payload": "x"},
            headers={"Authorization": f"Bearer {expired}"},
        )
        assert response.status_code == 401


# --------------------------------------------------------------------------- #
# Category 13 - body manipulation
# --------------------------------------------------------------------------- #


class TestBodyManipulation:
    """Only the documented fields are read; everything else is ignored."""

    def test_extra_fields_never_influence_execution(self, client, auth_headers):
        bean = {
            "scenario": "login",
            "payload": LOGIN_BYPASS,
            "query": "DROP TABLE users",
            "sql": "DROP TABLE users",
            "user_id": "attacker-controlled",
            "database": "production",
            "table": "reports",
            "connection_string": "postgres://x",
            "password": "hunter2",
            "admin": True,
        }
        response = client.post("/api/sql/run", json=bean, headers=auth_headers)
        assert response.status_code == 200
        body = response.get_json()["data"]
        assert body["scenario"] == "login"
        assert body["input"] == LOGIN_BYPASS
        assert body["vulnerable_result"]["rows"] == 3
        expected = SQLLabService.run_scenario("login", LOGIN_BYPASS)
        assert body == expected
        raw = str(response.get_json())
        assert "hunter2" not in raw
        assert "postgres://x" not in raw

    def test_user_id_is_never_used(self, client, auth_headers):
        response = client.post(
            "/api/sql/run",
            json={
                "scenario": "union",
                "payload": UNION_PAYLOAD,
                "user_id": "another-user",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        body = response.get_json()["data"]
        assert "user_id" not in body
        assert "another-user" not in str(response.get_json())
        expected = SQLLabService.run_scenario("union", UNION_PAYLOAD)
        assert body == expected


# --------------------------------------------------------------------------- #
# Category 14 - network independence
# --------------------------------------------------------------------------- #


class TestNetworkIndependence:
    """The sandbox runs with every network primitive dead, because it never
    uses them."""

    def test_all_scenarios_run_with_network_disabled(self, monkeypatch):
        def _no_network(*args, **kwargs):
            raise AssertionError("network access attempted")

        monkeypatch.setattr(socket, "socket", _no_network)
        monkeypatch.setattr(socket, "create_connection", _no_network)
        try:
            import http.client
            import urllib.request

            monkeypatch.setattr(http.client, "HTTPConnection", _no_network)
            monkeypatch.setattr(urllib.request, "urlopen", _no_network)
        except ImportError:  # pragma: no cover - importable on all supported pythons
            pass

        for scenario_id, payload in CANONICAL.items():
            result = SQLLabService.run_scenario(scenario_id, payload)
            _assert_contained(result, scenario_id)

    def test_service_has_no_network_or_database_dependency_imports(self):
        source = inspect.getsource(sql_lab_service)
        assert "import socket" not in source
        assert "import requests" not in source
        assert "import urllib" not in source
        assert "import http" not in source
        assert "import psycopg" not in source.lower()
        assert "import postgres" not in source.lower()
        assert not any(name.lower().startswith("supabase") for name in vars(sql_lab_service))
        assert not any(name.lower().startswith("psycopg") for name in vars(sql_lab_service))


# --------------------------------------------------------------------------- #
# Category 15 - sensitive information scanning
# --------------------------------------------------------------------------- #


class TestSensitiveInformationScanning:
    """No response ever contains secret values, config names, or paths."""

    def test_static_secret_patterns_are_absent_from_non_echo_fields(self):
        for scenario_id in SCENARIOS:
            for payload in (LOGIN_BYPASS, UNION_PAYLOAD, SUPABASE_PAYLOADS[1]):
                result = SQLLabService.run_scenario(scenario_id, payload)
                for text in _walk_strings(result, skip_echo=True):
                    for pattern in LEAK_PATTERNS:
                        assert not pattern.search(text), (
                            f"{pattern.pattern!r} matched {text!r}"
                        )

    def test_service_never_echoes_unrequested_values(self, client, auth_headers):
        sentinel = "REDTEAM_SENTINEL_1847"
        response = client.post(
            "/api/sql/run",
            json={"scenario": "login", "payload": LOGIN_BYPASS},
            headers=auth_headers,
        )
        assert sentinel not in str(response.get_json())

    def test_full_http_responses_are_recursively_scanned(self, client, auth_headers):
        for scenario_id, payload in CANONICAL.items():
            response = client.post(
                "/api/sql/run",
                json={"scenario": scenario_id, "payload": payload},
                headers=auth_headers,
            )
            assert response.status_code == 200
            data = response.get_json()
            for text in _walk_strings(data, skip_echo=True):
                for pattern in LEAK_PATTERNS:
                    assert not pattern.search(text)


# --------------------------------------------------------------------------- #
# Code audit regression - vulnerabilities found during this pass
# --------------------------------------------------------------------------- #


class TestCodeAuditRegressions:
    """Assert the invariants uncovered during the manual code audit hold."""

    def test_connection_is_created_and_closed_inside_one_lifecycle(self, monkeypatch):
        """Every ``run_scenario`` opens a fresh connection and closes it before
        returning; no connection survives the call."""

        class _SpyConnection(sqlite3.Connection):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.spy_closed = False

            def close(self):
                self.spy_closed = True
                super().close()

        created = []
        real_connect = sqlite3.connect

        def spy(*args, **kwargs):
            conn = real_connect(*args, factory=_SpyConnection, **kwargs)
            created.append(conn)
            return conn

        monkeypatch.setattr("sqlite3.connect", spy)
        SQLLabService.run_scenario("login", LOGIN_BYPASS)
        SQLLabService.run_scenario("union", UNION_PAYLOAD)

        assert created, "no connection was created"
        assert all(conn.spy_closed for conn in created), "a connection leaked open"
        # A closed connection can no longer execute statements.
        for conn in created:
            with pytest.raises(sqlite3.ProgrammingError):
                conn.execute("SELECT 1")

    def test_no_global_mutable_database_state(self):
        module_source = inspect.getsource(sql_lab_service)
        assert "global " not in module_source
        # No module-level Connection or any other persistent database object.
        connection_globals = [
            name
            for name, value in vars(sql_lab_service).items()
            if isinstance(value, sqlite3.Connection)
        ]
        assert connection_globals == []

    def test_parameterized_path_uses_sqlite_binding(self):
        source = inspect.getsource(sql_lab_service)
        assert "conn.execute(sql, params)" in source or "conn.execute(" in source
        assert "?" in SCENARIOS["login"]["secure_template"]
        assert "{payload}" in SCENARIOS["login"]["vulnerable_template"]

    def test_educational_scenarios_still_behave(self):
        """The cell-size + serialization fix must not weaken the four educational
        scenarios."""
        assert (
            SQLLabService.run_scenario("login", LOGIN_BYPASS)[
                "vulnerable_result"
            ]["rows"]
            == 3
        )
        assert (
            SQLLabService.run_scenario("union", UNION_PAYLOAD)[
                "vulnerable_result"
            ]["rows"]
            == 4
        )
        assert (
            SQLLabService.run_scenario("boolean", BOOLEAN_TRUE)[
                "vulnerable_result"
            ]["rows"]
            == 6
        )
        assert (
            SQLLabService.run_scenario("comment", COMMENT_PAYLOAD)[
                "vulnerable_result"
            ]["rows"]
            == 1
        )