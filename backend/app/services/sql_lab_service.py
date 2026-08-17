"""
SQL Lab Service (Phase 1) - isolated educational SQL injection sandbox.

Every execution is fully ephemeral:

- Each call opens a brand-new SQLite database via ``sqlite3.connect(":memory:")``.
- The connection exists only for the lifetime of the call and is always closed,
  so no state survives between executions (cross-user isolation).
- No SQLite files, no PostgreSQL, no Supabase, and no network are ever touched.
- The caller controls **only** a scenario id and a payload string. The schema,
  seed data, SQL templates, and scenario semantics are fixed here and cannot be
  altered by callers.
- There is deliberately **no** ``run_sql`` / ``query`` / arbitrary-SQL entry point.

Each run executes two distinct paths:

- vulnerable: the payload is interpolated into the fixed scenario template.
- secure:    the payload is passed through ``sqlite3`` parameter binding.

Defense-in-depth: a sandbox authorizer (read-only access to the demo tables, no
writes, no ATTACH/DETACH/PRAGMA, no load_extension), a progress handler that
aborts pathological work, capped result rows, engine-level per-cell size limits
and JSON-safe result cells, and safe generic error mapping.
"""

import contextlib
import sqlite3

from ..errors import ValidationError

# Sandbox description returned in every result payload.
SANDBOX_LABEL = "in-memory sqlite (isolated, non-persistent)"

# Dedicated SQL Playground limits. Sized for an educational lab and independent
# from the Cryptography Lab limits (CRYPTO_MAX_INPUT_LENGTH is never reused).
SQL_PAYLOAD_MAX_LENGTH = 2048
SQL_MAX_RESULT_ROWS = 100
SQL_MAX_STEPS = 100_000
# Maximum size of a single TEXT/BLOB cell a scenario may return. Enforced at
# the SQLite engine level (SQLITE_LIMIT_LENGTH) so pathological values such as
# ``zeroblob(1000000000)`` can never be materialized or serialized.
SQL_MAX_RESULT_CELL_SIZE = 1_000_000

# Tables an educational scenario is allowed to SELECT from. sqlite_master and
# every other table are denied by the authorizer.
DEMO_TABLES = ("users", "products", "orders")
_ALLOWED_READ_TABLES = frozenset(DEMO_TABLES)

SCHEMA_SQL = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    role TEXT
);

CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT,
    category TEXT,
    price REAL
);

CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    product_id INTEGER,
    quantity INTEGER
);
"""

# Deterministic benign seed data. No passwords, emails, tokens, or identifiers
# that resemble real users or application infrastructure.
SEED_SQL = """
INSERT INTO users (id, username, role) VALUES
    (1, 'alice', 'user'),
    (2, 'bob', 'user'),
    (3, 'admin', 'admin'),
    (4, 'carol', 'user');

INSERT INTO products (id, name, category, price) VALUES
    (1, 'USB Drive', 'storage', 9.99),
    (2, 'Portable SSD', 'storage', 49.90),
    (3, 'Webcam', 'video', 34.50),
    (4, 'Monitor Cable', 'video', 6.49),
    (5, 'Laptop Stand', 'accessory', 19.00),
    (6, 'Desk Lamp', 'accessory', 15.00);

INSERT INTO orders (id, user_id, product_id, quantity) VALUES
    (1, 1, 1, 2),
    (2, 1, 2, 1),
    (3, 2, 3, 1),
    (4, 4, 6, 4),
    (5, 3, 5, 1);
"""


# --------------------------------------------------------------------------- #
# Scenario catalog
# --------------------------------------------------------------------------- #
# Fixed catalog. Callers may list it read-only but can never create or modify
# scenarios or the bundled SQL templates.


def _secure_params_login(payload):
    """Secure (parameterized) login binds the payload as username."""
    return payload, "user"


def _secure_params_union(payload):
    """Secure (parameterized) product search binds the payload as category."""
    return (payload,)


def _secure_params_boolean(payload):
    """Secure (parameterized) search binds the payload inside a LIKE pattern."""
    return (f"%{payload}%",)


def _secure_params_comment(payload):
    """Secure (parameterized) login binds the payload as username."""
    return payload, "user"


SCENARIOS = {
    "login": {
        "id": "login",
        "name": "Login Authentication Bypass",
        "description": (
            "A login query interpolates the username directly into the SQL "
            "string. The classic \"' OR '1'='1\" payload escapes the string "
            "literal and adds an always-true condition, so the query returns "
            "every regular user account instead of a single matching row."
        ),
        "example_payload": "' OR '1'='1",
        "vulnerable_template": (
            "SELECT id, username, role FROM users "
            "WHERE username = '{payload}' AND role = 'user' ORDER BY id;"
        ),
        "secure_template": (
            "SELECT id, username, role FROM users "
            "WHERE username = ? AND role = ? ORDER BY id;"
        ),
        "secure_params_builder": _secure_params_login,
        "vulnerable_explanation": (
            "The payload is concatenated into the SQL string. The closing quote "
            "ends the ``username = ''`` literal and ``OR '1'='1`` injects an "
            "always-true condition, so the WHERE clause no longer restricts the "
            "query to a single matching username and every regular-user account "
            "is returned."
        ),
        "secure_explanation": (
            "The payload is bound as a parameter (``?`` placeholder). SQLite "
            "treats it purely as a value, so quote characters and operators in "
            "the input can never change the structure of the statement."
        ),
        "mitigation": (
            "Always use parameterized queries or an ORM with bind variables; "
            "never build SQL by string concatenation. Length-limit and validate "
            "inputs, and run the database with least-privilege accounts."
        ),
    },
    "union": {
        "id": "union",
        "name": "UNION-Based Data Extraction",
        "description": (
            "A product search concatenates the category into the query. A UNION "
            "payload appends a second SELECT over the users table, so "
            "attacker-controlled rows appear inside the legitimate result set."
        ),
        "example_payload": "' UNION SELECT username, role FROM users --",
        "vulnerable_template": (
            "SELECT name, price FROM products WHERE category = '{payload}';"
        ),
        "secure_template": "SELECT name, price FROM products WHERE category = ?;",
        "secure_params_builder": _secure_params_union,
        "vulnerable_explanation": (
            "The payload closes the string literal and appends ``UNION SELECT``, "
            "merging rows from the users table into the products result. The "
            "attacker shaped the query, not the developer."
        ),
        "secure_explanation": (
            "Binding the payload as a parameter means the injected text is just "
            "a value compared against the ``category`` column; it can never "
            "become part of the statement structure."
        ),
        "mitigation": (
            "Use parameter binding, restrict the database account to the "
            "tables/columns actually required, and avoid surfacing raw query "
            "results to end users."
        ),
    },
    "boolean": {
        "id": "boolean",
        "name": "Boolean-Based Blind Injection",
        "description": (
            "A search wraps the payload inside a LIKE pattern. Trailing quotes "
            "combined with AND conditions make the vulnerable query return "
            "different row counts based on a condition the attacker controls, "
            "demonstrating how an attacker can leak information one bit at a "
            "time (blind SQL injection)."
        ),
        "example_payload": "' AND 1=1 --",
        "vulnerable_template": (
            "SELECT id, name, price FROM products "
            "WHERE name LIKE '%{payload}%' ORDER BY id;"
        ),
        "secure_template": (
            "SELECT id, name, price FROM products WHERE name LIKE ? ORDER BY id;"
        ),
        "secure_params_builder": _secure_params_boolean,
        "vulnerable_explanation": (
            "Interpolating different boolean payloads (e.g. ``' AND 1=1 --`` vs "
            "``' AND 1=2 --``) changes the row set on the vulnerable path. An "
            "attacker can probe conditions inside the query to extract data one "
            "bit at a time."
        ),
        "secure_explanation": (
            "On the parameterized path the payload is one search term; both "
            "boolean conditions are treated as literal text and return the same "
            "non-matching result."
        ),
        "mitigation": (
            "Parameter binding makes injected conditions inert. Apply "
            "least-privilege database accounts and do not expose row-count "
            "differences or timings to unauthenticated clients."
        ),
    },
    "comment": {
        "id": "comment",
        "name": "Comment-Based Filter Bypass",
        "description": (
            "A login-style query appends filters and ordering after the "
            "interpolated value. The ``admin'--`` payload truncates the rest of "
            "the statement, removing the role restriction and returning the "
            "admin account."
        ),
        "example_payload": "admin'--",
        "vulnerable_template": (
            "SELECT id, username, role FROM users "
            "WHERE username = '{payload}' AND role = 'user' ORDER BY id;"
        ),
        "secure_template": (
            "SELECT id, username, role FROM users "
            "WHERE username = ? AND role = ? ORDER BY id;"
        ),
        "secure_params_builder": _secure_params_comment,
        "vulnerable_explanation": (
            "The ``--`` comment marker swallows the remainder of the fixed "
            "query, including the ``AND role = 'user'`` filter and the ORDER BY "
            "clause. The WHERE clause then evaluates only the attacker-controlled "
            "username and the admin account is returned regardless of role."
        ),
        "secure_explanation": (
            "Parameter binding keeps ``admin'--`` as a literal username value. "
            "SQLite never parses ``--`` inside a bound value, so no filter is "
            "bypassed and no row matches."
        ),
        "mitigation": (
            "Use parameter binding and treat comment markers in input as plain "
            "data. Enforce authorization in application code, not only inside "
            "the SQL filter."
        ),
    },
}


# --------------------------------------------------------------------------- #
# Sandboxing
# --------------------------------------------------------------------------- #


class _SandboxAuthorizer:
    """sqlite3 authorizer that keeps the educational SELECTs working while
    denying everything else (writes, schema changes, ATTACH/DETACH, PRAGMA,
    load_extension, and reads outside the demo tables)."""

    def __call__(self, action, arg1, arg2, dbname, source):
        if action == sqlite3.SQLITE_READ:
            if arg1 not in _ALLOWED_READ_TABLES:
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_TRANSACTION):
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_FUNCTION:
            # The runtime passes the function name in ``arg2``.
            if arg2 == "load_extension":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        # INSERT/UPDATE/DELETE/DROP/CREATE/ALTER/ATTACH/DETACH/PRAGMA and any
        # other capability are denied by default.
        return sqlite3.SQLITE_DENY


def _abort_progress():
    """Progress handler: aborts execution once the work budget is exceeded."""
    return 1


@contextlib.contextmanager
def _open_lab_database():
    """Create a fully isolated, ephemeral, seeded SQLite database.

    The connection is created and hardened entirely inside this context and is
    always closed on exit. Nothing about it exists before or after the call.
    """
    conn = None
    try:
        conn = sqlite3.connect(":memory:")
        conn.isolation_level = None  # autocommit; nothing is ever persisted
        conn.executescript(SCHEMA_SQL)
        conn.executescript(SEED_SQL)
        # Hardening is applied after seeding so the fixed setup still works.
        # Bound every returned TEXT/BLOB cell so oversized values (e.g. from
        # ``zeroblob``/``randomblob`` in a UNION payload) are rejected instead
        # of allocating huge buffers.
        conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, SQL_MAX_RESULT_CELL_SIZE)
        conn.set_progress_handler(_abort_progress, SQL_MAX_STEPS)
        conn.set_authorizer(_SandboxAuthorizer())
        yield conn
    finally:
        if conn is not None:
            conn.close()


# --------------------------------------------------------------------------- #
# Execution helpers
# --------------------------------------------------------------------------- #


def _sanitize_cell(value):
    """Make a result cell safe to serialize and bounded in size.

    SQLite can return binary blobs (e.g. ``zeroblob``/``randomblob`` from a
    UNION payload). Raw ``bytes`` are not JSON-serializable and would crash the
    response, so they are summarized as a fixed marker. Oversized text is
    truncated (belt-and-suspenders alongside ``SQLITE_LIMIT_LENGTH``).
    """
    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"[binary data: {len(value)} bytes]"
    if isinstance(value, str) and len(value) > SQL_MAX_RESULT_CELL_SIZE:
        return value[:SQL_MAX_RESULT_CELL_SIZE] + "[truncated]"
    return value


def _run_query(conn, sql, params=()):
    """Execute ``sql`` on the sandbox connection and return a safe structure.

    Returns a well-formed result dict. sqlite3 internals are never surfaced:
    failures are mapped to a generic ``rejection_reason`` string. Result cells
    are bounded and JSON-serializable.
    """
    try:
        cursor = conn.execute(sql, params)
        columns = [desc[0] for desc in cursor.description] if cursor.description else []
        data = [
            [_sanitize_cell(cell) for cell in row]
            for row in cursor.fetchmany(SQL_MAX_RESULT_ROWS)
        ]
        return {
            "rows": len(data),
            "columns": columns,
            "data": data,
            "execution_status": "ok",
        }
    except (sqlite3.DatabaseError, ValueError) as exc:
        return {
            "rows": 0,
            "columns": [],
            "data": [],
            "execution_status": "rejected",
            "rejection_reason": _safe_rejection_reason(exc),
        }


def _safe_rejection_reason(exc):
    """Return a safe, generic reason for a sandbox rejection.

    Internal sqlite text (messages, class names), filesystem paths, and
    implementation details are never forwarded.
    """
    message = str(exc).lower()
    if "only execute one statement" in message:
        return "multiple statements are not allowed"
    if "not authorized" in message:
        return "blocked by the sandbox guard"
    if "interrupted" in message:
        return "maximum query work exceeded"
    if "syntax error" in message or " near " in message or 'near "' in message:
        return "SQL syntax was rejected"
    return "the query could not be executed inside the sandbox"


def _what_happened(scenario, vulnerable, safe):
    """Build the scenario-aware narrative for this specific run."""
    if vulnerable["execution_status"] == "rejected":
        return (
            "The vulnerable query could not be completed: the payload was "
            f"{vulnerable['rejection_reason']}. The same payload was then bound "
            f"as a parameter and was treated as data, returning {safe['rows']} "
            "row(s) instead of changing the query structure."
        )
    return (
        f"The payload was interpolated into the fixed template, and the "
        f"vulnerable path returned {vulnerable['rows']} row(s). The same payload "
        f"passed through parameter binding was treated as data and returned "
        f"{safe['rows']} row(s): its SQL metacharacters had no effect on the "
        "parameterized query."
    )


# --------------------------------------------------------------------------- #
# Input validation
# --------------------------------------------------------------------------- #


def _validate_payload(payload, max_length):
    if payload is None:
        raise ValidationError("'payload' is required", details={"field": "payload"})
    if not isinstance(payload, str):
        raise ValidationError(
            "'payload' must be a string",
            details={"field": "payload", "type": type(payload).__name__},
        )
    if len(payload) > max_length:
        raise ValidationError(
            f"'payload' exceeds the maximum length of {max_length} characters",
            details={"field": "payload", "max_length": max_length},
        )
    return payload


def _resolve_scenario(scenario_id):
    supported = ", ".join(sorted(SCENARIOS))
    if not isinstance(scenario_id, str) or scenario_id not in SCENARIOS:
        raise ValidationError(
            f"Unknown SQL lab scenario '{scenario_id}'. Supported: {supported}",
            details={"field": "scenario"},
        )
    return SCENARIOS[scenario_id]


# --------------------------------------------------------------------------- #
# Public service
# --------------------------------------------------------------------------- #


class SQLLabService:
    """Isolated, in-memory SQL injection laboratory.

    Deterministic and side-effect free: every call builds a fresh ``:memory:``
    database, runs the fixed vulnerable + secure paths, and returns an
    educational comparison without touching any persistent system.
    """

    @staticmethod
    def run_scenario(scenario_id, payload, max_length=SQL_PAYLOAD_MAX_LENGTH):
        """Run one fixed educational scenario against an ephemeral database.

        Args:
            scenario_id: one of the fixed scenario ids (see
                :meth:`available_scenarios`).
            payload: the attacker-controlled string. ONLY this value is caller
                controlled; the schema, seed data, and SQL templates are fixed.
            max_length: maximum payload length (defaults to the dedicated
                ``SQL_PAYLOAD_MAX_LENGTH`` constant).

        Returns:
            A dictionary with the vulnerable vs. secure queries, their results,
            and educational explanations (see module docstring / tests).

        Raises:
            ValidationError: for a missing/non-string/over-long payload or an
                unknown scenario. Execution failures inside the sandbox are
                never raised; they are reported generically in the result.
        """
        scenario = _resolve_scenario(scenario_id)
        _validate_payload(payload, max_length)

        vulnerable_query = scenario["vulnerable_template"].format(payload=payload)
        secure_query = scenario["secure_template"]
        secure_params = scenario["secure_params_builder"](payload)

        with _open_lab_database() as conn:
            vulnerable = _run_query(conn, vulnerable_query)
            safe = _run_query(conn, secure_query, params=secure_params)

        return {
            "scenario": scenario_id,
            "input": payload,
            "vulnerable_query": vulnerable_query,
            "safe_query": secure_query,
            "vulnerable_result": vulnerable,
            "safe_result": safe,
            "explanation": {
                "what_happened": _what_happened(scenario, vulnerable, safe),
                "why_vulnerable": scenario["vulnerable_explanation"],
                "why_safe": scenario["secure_explanation"],
                "mitigation": scenario["mitigation"],
            },
            "sandbox": SANDBOX_LABEL,
        }

    @staticmethod
    def available_scenarios():
        """Return a read-only copy of the fixed scenario catalog.

        The bundled SQL templates belong to the service and cannot be modified
        by callers.
        """
        return {
            scenario_id: {
                "id": scenario["id"],
                "name": scenario["name"],
                "description": scenario["description"],
                "example_payload": scenario["example_payload"],
                "vulnerable_explanation": scenario["vulnerable_explanation"],
                "secure_explanation": scenario["secure_explanation"],
                "mitigation": scenario["mitigation"],
                "vulnerable_template": scenario["vulnerable_template"],
                "secure_template": scenario["secure_template"],
            }
            for scenario_id, scenario in SCENARIOS.items()
        }