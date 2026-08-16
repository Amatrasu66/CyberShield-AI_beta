"""
Dashboard Service.

Aggregates the authenticated user's persisted scan and report data from Supabase
into the summary payload consumed by the frontend Dashboard page.

All reads run through a user-scoped client authenticated with the request's
access token, so Row Level Security keeps every query scoped to ``auth.uid()``.
``user_id`` always comes from the verified JWT; it is never read from the
request body or query string. The elevated admin client is never used.

Privacy guarantees mirror the write services: passwords, password hashes, raw
email content and raw log content are never returned by this endpoint.
"""

from datetime import datetime, timedelta, timezone

from ..database import get_user_supabase_client
from ..errors import ServiceUnavailableError, ValidationError
from ..middleware.auth_middleware import get_current_access_token

SCAN_TABLES = ("website_scans", "email_scans", "password_scans", "log_scans")

RECENT_SCANS_LIMIT = 10
ACTIVITY_LIMIT = 10
TREND_DAYS = 12

THREAT_RISK_LEVELS = ("high", "critical")
WEAK_PASSWORD_LABELS = ("Weak", "Fair")

METRIC_TONES = {
    "security_score": "success",
    "scans_completed": "primary",
    "threats_detected": "danger",
    "assets_monitored": "warning",
}

# Display risk only (recent scans table); not a threat-metric rule.
PASSWORD_RISK = {"Weak": "high", "Fair": "medium", "Good": "low", "Strong": "low"}


def _extract_data(result) -> list:
    """Extract the ``data`` list from a supabase ``execute()`` result."""
    if result is None:
        return []
    if isinstance(result, dict):
        data = result.get("data")
    else:
        data = getattr(result, "data", None)
    return data or []


def _parse_timestamp(value):
    """Parse an ISO-8601 timestamp into an aware UTC ``datetime`` (or ``None``)."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _start_of_week_utc(now=None) -> datetime:
    """Midnight of the current Monday in UTC."""
    now = now or datetime.now(timezone.utc)
    monday = now - timedelta(days=now.weekday())
    return monday.replace(hour=0, minute=0, second=0, microsecond=0)


def _fetch_rows(client, table: str, user_id: str) -> list:
    """Return the user's rows for ``table``, newest first, or raise 503."""
    try:
        result = (
            client.table(table)
            .select("*")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .execute()
        )
    except Exception as exc:
        raise ServiceUnavailableError(
            "Dashboard data could not be retrieved",
            details={"table": table, "error": type(exc).__name__},
        ) from exc
    return _extract_data(result)


def _security_score(website_rows: list) -> dict:
    """Average ``security_score`` across the user's website scans."""
    scores = [row.get("security_score") for row in website_rows]
    scores = [s for s in scores if isinstance(s, (int, float)) and s is not None]
    value = round(sum(scores) / len(scores)) if scores else 0
    detail = (
        f"Average across {len(scores)} website scan(s)"
        if scores
        else "No website scans on file"
    )
    return {"value": value, "detail": detail, "tone": METRIC_TONES["security_score"]}


def _scans_completed_all_tables(rows_by_table: dict) -> list:
    """Flatten scan rows across the four scan tables."""
    rows = []
    for table in SCAN_TABLES:
        rows.extend(rows_by_table.get(table) or [])
    return rows


def _scans_completed(rows_by_table: dict, week_start=None) -> dict:
    rows = _scans_completed_all_tables(rows_by_table)
    total = len(rows)
    week_start = week_start or _start_of_week_utc()
    this_week = 0
    for row in rows:
        ts = _parse_timestamp(row.get("created_at"))
        if ts is not None and ts >= week_start:
            this_week += 1
    return {
        "value": total,
        "detail": f"{this_week} this week",
        "tone": METRIC_TONES["scans_completed"],
    }


def _is_threat(table: str, row: dict) -> bool:
    """Whether a scan row represents a genuinely risky result."""
    if table in ("website_scans", "email_scans", "log_scans"):
        return row.get("risk_level") in THREAT_RISK_LEVELS
    if table == "password_scans":
        breached = bool(row.get("breached"))
        label = row.get("strength_label")
        weak = isinstance(label, str) and label in WEAK_PASSWORD_LABELS
        return breached or weak
    return False


def _threats_detected(rows_by_table: dict) -> dict:
    threats = 0
    for table in SCAN_TABLES:
        for row in rows_by_table.get(table) or []:
            if _is_threat(table, row):
                threats += 1
    return {
        "value": threats,
        "detail": f"{threats} require attention",
        "tone": METRIC_TONES["threats_detected"],
    }


def _assets_monitored(website_rows: list) -> dict:
    """Distinct ``target_url`` values across the user's website scans."""
    targets = {
        row.get("target_url")
        for row in website_rows
        if isinstance(row.get("target_url"), str) and row["target_url"].strip()
    }
    value = len(targets)
    detail = (
        f"{value} distinct target(s) monitored"
        if targets
        else "No targets monitored yet"
    )
    return {"value": value, "detail": detail, "tone": METRIC_TONES["assets_monitored"]}


def _display_risk(table: str, row: dict) -> str:
    """Human-friendly risk value for the recent-scans table."""
    if table == "password_scans":
        if row.get("breached"):
            return "high"
        return PASSWORD_RISK.get(row.get("strength_label"), "low")
    level = row.get("risk_level")
    return level or "unknown"


def _normalize_scan(table: str, row: dict) -> dict:
    """Map a stored scan row to the Dashboard's recent-scans shape."""
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


def _recent_scans(rows_by_table: dict) -> list:
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


def _activity_scan_message(table: str, row: dict) -> str:
    if table == "website_scans":
        target = row.get("target_url") or "a target"
        return f"Website scan completed for {target}"
    if table == "email_scans":
        return "Email analysis completed"
    if table == "password_scans":
        return "Password analysis completed"
    return "Log analysis completed"


def _activity(rows_by_table: dict, report_rows: list) -> list:
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
            {"message": f"Report generated: {title}", "created_at": report.get("created_at")}
        )
    items.sort(
        key=lambda item: _parse_timestamp(item.get("created_at"))
        or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return items[:ACTIVITY_LIMIT]


def _trend(rows_by_table: dict, today=None) -> dict:
    """Scan counts per day over the last 12 calendar days (UTC), including zeros."""
    now = today or datetime.now(timezone.utc).date()
    days = [now - timedelta(days=offset) for offset in range(TREND_DAYS - 1, -1, -1)]
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


class DashboardService:
    """Aggregate the authenticated user's scans and reports for the Dashboard."""

    @staticmethod
    def get_dashboard(user_id: str = None) -> dict:
        """Return metrics, recent scans, activity and trend for the user.

        Raises:
            ValidationError: when no ``user_id`` is supplied.
            ServiceUnavailableError: when Supabase is unavailable or a read
                fails.
        """
        if not user_id:
            raise ValidationError(
                "A valid authenticated user is required to load the dashboard",
                details={"field": "user_id"},
            )

        client = get_user_supabase_client(get_current_access_token())
        if client is None:
            raise ServiceUnavailableError(
                "Dashboard data is unavailable (Supabase not configured)",
                code="DASHBOARD_UNAVAILABLE",
            )

        rows_by_table = {
            table: _fetch_rows(client, table, user_id) for table in SCAN_TABLES
        }
        report_rows = _fetch_rows(client, "reports", user_id)

        return {
            "metrics": {
                "security_score": _security_score(rows_by_table["website_scans"]),
                "scans_completed": _scans_completed(rows_by_table),
                "threats_detected": _threats_detected(rows_by_table),
                "assets_monitored": _assets_monitored(rows_by_table["website_scans"]),
            },
            "recent_scans": _recent_scans(rows_by_table),
            "activity": _activity(rows_by_table, report_rows),
            "trend": _trend(rows_by_table),
        }