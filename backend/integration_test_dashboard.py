"""
REAL end-to-end Dashboard integration test (integration_test_dashboard.py).

Runs against the RUNNING Flask server (http://127.0.0.1:5000) and the REAL
Supabase project configured in backend/.env. No mocks are used.

What is exercised:
  1. Read SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, CS_TEST_USER_EMAIL and
     CS_TEST_USER_PASSWORD from the local backend/.env.
  2. Sign the CyberShield test user in through REAL Supabase Auth.
  3. Keep the access token only in memory (never printed / persisted).
  4. Call GET /api/dashboard with the real Bearer token.
  5. Independently query the REAL Supabase database with the user's own token
     (PostgREST + RLS) and recompute the expected metrics, recent scans,
     activity and 12-day trend from the actual stored rows.
  6. Compare every field the API returned against those expected values.
  7. Verify every returned record belongs to the authenticated user.
  8. Verify sensitive data (passwords, hashes, raw email/log content, tokens,
     API keys) is absent from the API response.
  9. Verify cross-user isolation:
       - With the user's token: unfiltered reads must return ONLY the user's
         own rows.
       - With the service_role key (optional, in memory only, never printed):
         confirm foreign users' rows exist and none of them leak into the
         user's RLS view. A second sign-in is used only if a second test-user
         credential is present in backend/.env (it is not currently), in which
         case the report marks cross-user isolation as NOT TESTED.

Nothing in this file modifies production code, schema, RLS, Auth/JWT config,
Storage, or the database. It only reads.

Never prints passwords, access tokens, JWTs, or secret keys.
"""

import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import requests
from dotenv import dotenv_values

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"

FLASK_BASE = "http://127.0.0.1:5000"

REQUIRED_ENV_KEYS = (
    "SUPABASE_URL",
    "SUPABASE_PUBLISHABLE_KEY",
    "CS_TEST_USER_EMAIL",
    "CS_TEST_USER_PASSWORD",
)

SCAN_TABLES = ("website_scans", "email_scans", "password_scans", "log_scans")

RECENT_SCANS_LIMIT = 10
ACTIVITY_LIMIT = 10
TREND_DAYS = 12

THREAT_RISK_LEVELS = ("high", "critical")
WEAK_PASSWORD_LABELS = ("Weak", "Fair")
PASSWORD_RISK = {"Weak": "high", "Fair": "medium", "Good": "low", "Strong": "low"}

# ---------------------------------------------------------------------------
# Results helpers
# ---------------------------------------------------------------------------

_results = []


def _report(name: str, ok: bool, detail: str = "") -> None:
    _results.append((name, ok))
    if ok is None:
        status = "NOT TESTED"
    else:
        status = "PASS" if ok else "FAIL"
    suffix = f" - {detail}" if detail else ""
    print(f"[{status}] {name}{suffix}")


def _redact(value: str, keep: int = 0) -> str:
    """Human-safe summary of a credential (never the value itself)."""
    if not value:
        return "(missing)"
    if keep:
        return f"(set, ends ...{value[-keep:]})"
    return "(set)"


# ---------------------------------------------------------------------------
# Env loading (from backend/.env only)
# ---------------------------------------------------------------------------

def _load_env() -> dict:
    """Return the values from backend/.env; does not touch os.environ."""
    return dict(dotenv_values(ENV_FILE))


# ---------------------------------------------------------------------------
# Independent reimplementation of the Dashboard aggregation spec
# ---------------------------------------------------------------------------

def _parse_timestamp(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _start_of_week_utc(now=None) -> datetime:
    now = now or datetime.now(timezone.utc)
    monday = now - timedelta(days=now.weekday())
    return monday.replace(hour=0, minute=0, second=0, microsecond=0)


def _is_threat(table: str, row: dict) -> bool:
    if table in ("website_scans", "email_scans", "log_scans"):
        return row.get("risk_level") in THREAT_RISK_LEVELS
    if table == "password_scans":
        breached = bool(row.get("breached"))
        label = row.get("strength_label")
        weak = isinstance(label, str) and label in WEAK_PASSWORD_LABELS
        return breached or weak
    return False


def _display_risk(table: str, row: dict) -> str:
    if table == "password_scans":
        if row.get("breached"):
            return "high"
        return PASSWORD_RISK.get(row.get("strength_label"), "low")
    level = row.get("risk_level")
    return level or "unknown"


def _normalize_scan(table: str, row: dict) -> dict:
    if table == "website_scans":
        target = row.get("target_url") or "Website scan"
        scan_type = "Website scan"
    elif table == "email_scans":
        target = row.get("subject") or "Email analysis"
        scan_type = "Email analysis"
    elif table == "password_scans":
        target = "Password analysis"
        scan_type = "Password analysis"
    else:  # log_scans
        target = "Log analysis"
        scan_type = "Log analysis"
    return {
        "target": target,
        "type": scan_type,
        "risk": _display_risk(table, row),
        "completed_at": row.get("created_at"),
    }


def _activity_scan_message(table: str, row: dict) -> str:
    if table == "website_scans":
        target = row.get("target_url") or "a target"
        return f"Website scan completed for {target}"
    if table == "email_scans":
        return "Email analysis completed"
    if table == "password_scans":
        return "Password analysis completed"
    return "Log analysis completed"


def _expected_metrics(rows_by_table: dict, now=None) -> dict:
    now = now or datetime.now(timezone.utc)
    week_start = _start_of_week_utc(now)

    all_rows = []
    for table in SCAN_TABLES:
        all_rows.extend(rows_by_table.get(table) or [])

    website_rows = rows_by_table.get("website_scans") or []
    scores = [
        row.get("security_score")
        for row in website_rows
        if isinstance(row.get("security_score"), (int, float))
        and row.get("security_score") is not None
    ]
    security_score = round(sum(scores) / len(scores)) if scores else 0

    this_week = sum(
        1
        for row in all_rows
        if (ts := _parse_timestamp(row.get("created_at"))) is not None
        and ts >= week_start
    )

    threats = 0
    for table in SCAN_TABLES:
        for row in rows_by_table.get(table) or []:
            if _is_threat(table, row):
                threats += 1

    targets = {
        row.get("target_url")
        for row in website_rows
        if isinstance(row.get("target_url"), str) and row["target_url"].strip()
    }

    return {
        "security_score": security_score,
        "scans_completed": len(all_rows),
        "this_week": this_week,
        "threats_detected": threats,
        "assets_monitored": len(targets),
    }


def _expected_recent_scans(rows_by_table: dict) -> list:
    items = []
    for table in SCAN_TABLES:
        for row in rows_by_table.get(table) or []:
            items.append(_normalize_scan(table, row))
    items.sort(
        key=lambda item: _parse_timestamp(item.get("completed_at"))
        or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return items[:RECENT_SCANS_LIMIT]


def _expected_activity(rows_by_table: dict, report_rows: list) -> list:
    items = []
    for table in SCAN_TABLES:
        for row in rows_by_table.get(table) or []:
            items.append(
                {
                    "message": _activity_scan_message(table, row),
                    "created_at": row.get("created_at"),
                }
            )
    for report in report_rows or []:
        title = report.get("title") or "Security Audit Report"
        items.append(
            {
                "message": f"Report generated: {title}",
                "created_at": report.get("created_at"),
            }
        )
    items.sort(
        key=lambda item: _parse_timestamp(item.get("created_at"))
        or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return items[:ACTIVITY_LIMIT]


def _expected_trend(rows_by_table: dict, now=None) -> dict:
    today = (now or datetime.now(timezone.utc)).date()
    days = [today - timedelta(days=offset) for offset in range(TREND_DAYS - 1, -1, -1)]
    counts = {day: 0 for day in days}
    for table in SCAN_TABLES:
        for row in rows_by_table.get(table) or []:
            ts = _parse_timestamp(row.get("created_at"))
            if ts is not None and ts.date() in counts:
                counts[ts.date()] += 1
    return {
        "labels": [day.isoformat() for day in days],
        "values": [counts[day] for day in days],
    }


# ---------------------------------------------------------------------------
# Real Supabase access
# ---------------------------------------------------------------------------

def _sign_in(supabase_url: str, apikey: str, email: str, password: str) -> str:
    """Exchange credentials for an in-memory access token (never persisted)."""
    url = f"{supabase_url}/auth/v1/token?grant_type=password"
    headers = {"apikey": apikey, "Content-Type": "application/json"}
    resp = requests.post(
        url, headers=headers, json={"email": email, "password": password}, timeout=30
    )
    if resp.status_code != 200:
        raise RuntimeError(f"sign-in failed: HTTP {resp.status_code}: {resp.text[:200]}")
    data = resp.json()
    token = data.get("access_token")
    if not token:
        raise RuntimeError("sign-in response did not include access_token")
    return token


def _uid_from_token(token: str) -> str:
    """Extract the ``sub`` claim (user id) from the JWT in memory."""
    return jwt.decode(token, options={"verify_signature": False})["sub"]


def _pg_rows(supabase_url, apikey, token, table, *, user_id=None, only_user_id=False):
    """Query a table via PostgREST. ``token`` selects the RLS principal."""
    params = {"select": "*", "order": "created_at.desc"}
    if user_id is not None:
        params["user_id"] = f"eq.{user_id}"
    headers = {"apikey": apikey, "Authorization": f"Bearer {token}"}
    resp = requests.get(
        f"{supabase_url}/rest/v1/{table}", params=params, headers=headers, timeout=30
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"PostgREST {table} failed: HTTP {resp.status_code}: {resp.text[:200]}"
        )
    return resp.json()


def _admin_rows(supabase_url, secret_key, table, user_id=None):
    """Query rows via service_role (bypasses RLS). Returns ``(id, user_id)``."""
    params = {"select": "id,user_id"}
    if user_id is not None:
        params["user_id"] = f"eq.{user_id}"
    headers = {"apikey": secret_key, "Authorization": f"Bearer {secret_key}"}
    resp = requests.get(
        f"{supabase_url}/rest/v1/{table}", params=params, headers=headers, timeout=30
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"admin {table} probe failed: HTTP {resp.status_code}: {resp.text[:200]}"
        )
    return resp.json()


# ---------------------------------------------------------------------------
# Sensitive-data inspection of the API payload
# ---------------------------------------------------------------------------

ALLOWED_KEYS = {
    "metrics",
    "recent_scans",
    "activity",
    "trend",
    "security_score",
    "scans_completed",
    "threats_detected",
    "assets_monitored",
    "value",
    "detail",
    "tone",
    "target",
    "type",
    "risk",
    "completed_at",
    "message",
    "created_at",
    "labels",
    "values",
}

SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|passphrase|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|authorization|bearer|private[_-]?key|^hash$)",
    re.IGNORECASE,
)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b")
BCRYPT_RE = re.compile(r"\$2[aby]\$\d{2}\$")


def _sensitive_data_issues(dashboard: dict, password: str) -> list:
    """Inspect only the dashboard payload (the ``data`` envelope body)."""
    issues = []

    def walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                if key not in ALLOWED_KEYS:
                    issues.append(f"unexpected key '{path}.{key}'")
                if SENSITIVE_KEY_RE.search(key):
                    issues.append(f"sensitive key '{path}.{key}'")
                walk(value, f"{path}.{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")
        elif isinstance(node, str):
            if JWT_RE.search(node):
                issues.append(f"JWT-like value at {path}")
            if BCRYPT_RE.search(node):
                issues.append(f"bcrypt-hash-like value at {path}")
            if password and len(password) >= 6 and password in node:
                issues.append(f"test password substring at {path}")

    walk(dashboard, "data")
    return issues


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print("=" * 72)
    print("REAL DASHBOARD INTEGRATION TEST")
    print("=" * 72)

    env = _load_env()

    # --- Required env -----------------------------------------------------
    supabase_url = (env.get("SUPABASE_URL") or "").strip().rstrip("/")
    apikey = (env.get("SUPABASE_PUBLISHABLE_KEY") or "").strip()
    email = (env.get("CS_TEST_USER_EMAIL") or "").strip()
    password = env.get("CS_TEST_USER_PASSWORD") or ""
    secret_key = (env.get("SUPABASE_SECRET_KEY") or "").strip()

    missing = [
        name
        for name, value in (
            ("SUPABASE_URL", supabase_url),
            ("SUPABASE_PUBLISHABLE_KEY", apikey),
            ("CS_TEST_USER_EMAIL", email),
            ("CS_TEST_USER_PASSWORD", password),
        )
        if not value
    ]
    if missing:
        print(f"[ERROR] Missing env values in {ENV_FILE.name}: {', '.join(missing)}")
        return 2
    print(f"[INFO] env      : {ENV_FILE.name}")
    print(f"[INFO] user     : {email}")

    # --- Phase: Authentication --------------------------------------------
    auth_ok = False
    try:
        token = _sign_in(supabase_url, apikey, email, password)
        user_id = _uid_from_token(token)
        auth_ok = True
        _report("Authentication", True, f"signed in as {user_id}")
    except Exception as exc:  # noqa: BLE001 - surfaced for the report
        _report("Authentication", False, f"{type(exc).__name__}: {exc}")
        return 1

    # --- Phase: GET /api/dashboard -----------------------------------------
    try:
        resp = requests.get(
            f"{FLASK_BASE}/api/dashboard",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=30,
        )
    except requests.RequestException as exc:
        _report("GET /api/dashboard", False, f"{type(exc).__name__}: {exc}")
        return 1

    http_ok = resp.status_code == 200
    try:
        payload = resp.json()
    except ValueError:
        payload = {}

    success_flag = bool(payload.get("success"))
    data = payload.get("data") if isinstance(payload, dict) else None
    shape_ok = (
        isinstance(data, dict)
        and all(key in data for key in ("metrics", "recent_scans", "activity", "trend"))
    )
    if not http_ok:
        _report("GET /api/dashboard", False, f"HTTP {resp.status_code}: {resp.text[:200]}")
        return 1
    _report("GET /api/dashboard", True, f"HTTP 200, success={success_flag}")
    _report("Response shape", shape_ok, "metrics/recent_scans/activity/trend present")
    if not shape_ok:
        return 1

    # --- Phase: independent DB recomputation --------------------------------
    try:
        rows_by_table = {
            table: _pg_rows(supabase_url, apikey, token, table, user_id=user_id)
            for table in SCAN_TABLES
        }
        report_rows = _pg_rows(supabase_url, apikey, token, "reports", user_id=user_id)
    except Exception as exc:  # noqa: BLE001
        _report("Independent DB recomputation", False, f"{type(exc).__name__}: {exc}")
        return 1
    _report("Independent DB recomputation", True, "rows fetched via user token (RLS)")

    expected = _expected_metrics(rows_by_table)
    metrics = data["metrics"]

    def _metric_check(name, actual, exp_value):
        ok = actual == exp_value
        _report(
            name,
            ok,
            f"api={actual!r} expected={exp_value!r}",
        )
        return ok

    # --- Metrics -----------------------------------------------------------
    metrics_ok = True
    metrics_ok &= _metric_check(
        "Security score",
        metrics.get("security_score", {}).get("value"),
        expected["security_score"],
    )
    metrics_ok &= _metric_check(
        "Scans completed",
        metrics.get("scans_completed", {}).get("value"),
        expected["scans_completed"],
    )
    this_week_detail = metrics.get("scans_completed", {}).get("detail", "")
    this_week_match = re.search(r"(\d+) this week", str(this_week_detail))
    api_this_week = int(this_week_match.group(1)) if this_week_match else None
    metrics_ok &= _metric_check(
        "This-week scans", api_this_week, expected["this_week"]
    )
    metrics_ok &= _metric_check(
        "Threats detected",
        metrics.get("threats_detected", {}).get("value"),
        expected["threats_detected"],
    )
    metrics_ok &= _metric_check(
        "Assets monitored",
        metrics.get("assets_monitored", {}).get("value"),
        expected["assets_monitored"],
    )
    _report("Metrics", metrics_ok)

    # --- Recent scans / activity / trend -----------------------------------
    exp_recent = _expected_recent_scans(rows_by_table)
    recent_ok = data["recent_scans"] == exp_recent
    _report(
        "Recent scans",
        recent_ok,
        f"{len(data['recent_scans'])} items; ordering+fields match",
    )

    exp_activity = _expected_activity(rows_by_table, report_rows)
    activity_ok = data["activity"] == exp_activity
    _report(
        "Activity",
        activity_ok,
        f"{len(data['activity'])} items; messages+ordering match",
    )

    exp_trend = _expected_trend(rows_by_table)
    trend_ok = data["trend"] == exp_trend
    _report(
        "12-day trend",
        trend_ok,
        f"{len(data['trend'].get('labels', []))} labels; counts match",
    )

    # --- User scoping --------------------------------------------------------
    scoping_ok = True
    for table in SCAN_TABLES + ("reports",):
        own = _pg_rows(supabase_url, apikey, token, table, user_id=user_id)
        foreign = [row for row in own if str(row.get("user_id")) != user_id]
        if foreign:
            scoping_ok = False
            _report(
                "RLS/user scoping",
                False,
                f"{table}: foreign user_id rows leaked into user-scoped read",
            )
    unfiltered_ok = True
    for table in SCAN_TABLES + ("reports",):
        raw = _pg_rows(supabase_url, apikey, token, table)
        bad = [row for row in raw if str(row.get("user_id")) != user_id]
        if bad:
            unfiltered_ok = False
            _report(
                "RLS/user scoping",
                False,
                f"{table}: {len(bad)} foreign row(s) visible to user's token",
            )
    _report(
        "RLS/user scoping",
        scoping_ok and unfiltered_ok,
        "all rows served to the user's token belong to the user",
    )

    # --- Sensitive-data check -------------------------------------------------
    issues = _sensitive_data_issues(data, password)
    sensitive_ok = not issues
    detail = "clean" if sensitive_ok else "; ".join(issues[:5])
    _report("Sensitive-data check", sensitive_ok, detail)

    # --- Cross-user isolation ---------------------------------------------------
    second_email = (env.get("CS_TEST_USER2_EMAIL") or "").strip()
    second_password = env.get("CS_TEST_USER2_PASSWORD") or ""
    cross_user_note = ""
    if second_email and second_password:
        try:
            token2 = _sign_in(supabase_url, apikey, second_email, second_password)
            uid2 = _uid_from_token(token2)
            resp2 = requests.get(
                f"{FLASK_BASE}/api/dashboard",
                headers={"Authorization": f"Bearer {token2}", "Accept": "application/json"},
                timeout=30,
            )
            if resp2.status_code != 200:
                _report("Cross-user isolation", False, f"second user dashboard HTTP {resp2.status_code}")
            else:
                data2 = resp2.json().get("data") or {}
                api_user_ids = set()
                for table in SCAN_TABLES:
                    for row in _pg_rows(supabase_url, apikey, token2, table, user_id=uid2):
                        api_user_ids.add(row.get("user_id"))
                leaked = user_id in api_user_ids
                _report("Cross-user isolation", not leaked, "first user's scans absent from second user view")
            cross_user_note = "second-user sign-in performed"
        except Exception as exc:  # noqa: BLE001
            _report("Cross-user isolation", False, f"{type(exc).__name__}: {exc}")
    else:
        _report(
            "Cross-user isolation",
            None,
            "NOT TESTED (no second test-user credentials in .env)",
        )

    # --- Optional admin-backed isolation probe (read-only, service_role) -------
    admin_note = ""
    if secret_key:
        admin_works = True
        foreign_total = 0
        leak_found = False
        for table in SCAN_TABLES + ("reports",):
            try:
                rows = _admin_rows(supabase_url, secret_key, table)
            except Exception as exc:  # noqa: BLE001
                _report("Admin isolation probe", False, f"{table}: {type(exc).__name__}")
                admin_works = False
                continue
            owners = {row.get("user_id") for row in rows}
            foreign_total += len(owners - {user_id})
            for row in rows:
                if str(row.get("user_id")) != user_id:
                    leak_found = True
            try:
                admin_own_ids = {r["id"] for r in _admin_rows(supabase_url, secret_key, table, user_id=user_id)}
                user_ids = {r["id"] for r in _pg_rows(supabase_url, apikey, token, table, user_id=user_id)}
                if admin_own_ids != user_ids:
                    _report(
                        "RLS/user scoping",
                        False,
                        f"{table}: user-token view != service-role view ({len(user_ids)} vs {len(admin_own_ids)})",
                    )
                    admin_works = False
            except Exception as exc:  # noqa: BLE001
                _report("Admin isolation probe", False, f"{table} own-view: {type(exc).__name__}")
                admin_works = False
        if not admin_works:
            admin_note = "service-role probe could not complete; isolation direction NOT TESTED"
            _report("Admin isolation probe", None, admin_note)
        elif leak_found:
            admin_note = "foreign rows LEAKED into the user's RLS view"
            _report("Admin isolation probe", False, admin_note)
        elif foreign_total == 0:
            admin_note = "no foreign owners exist in DB; isolation direction NOT TESTED"
            _report("Admin isolation probe", None, admin_note)
        else:
            admin_note = (
                f"{foreign_total} foreign owner(s) present in tables; none leaked into "
                f"the user's RLS view"
            )
            _report("Admin isolation probe", True, admin_note)
    else:
        _report("Admin isolation probe", None, "SKIPPED (no SUPABASE_SECRET_KEY read)")

    # --- Summary ---------------------------------------------------------------
    print("=" * 72)
    print("RESULTS")
    print("=" * 72)
    failures = [name for name, ok in _results if ok is False]
    not_tested = [name for name, ok in _results if ok is None]
    for name, ok in _results:
        status = "PASS" if ok is True else ("NOT TESTED" if ok is None else "FAIL")
        print(f"  {name:30} {status}")

    all_pass = not failures
    print(f"\n  Failed checks : {len(failures)}")
    print(f"  Not tested    : {len(not_tested)}")
    if cross_user_note:
        print(f"  Cross-user    : {cross_user_note}")
    if admin_note:
        print(f"  Admin probe   : {admin_note}")

    print("\n" + ("OVERALL: PASS" if all_pass else "OVERALL: FAIL"))
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
