"""
Security Report Service.

Generates PDF security reports from the authenticated user's persisted scan
data in Supabase and stores them in ``public.reports``.

Generation pipeline:
1. Read the user's most recent scans from ``website_scans``, ``email_scans``,
   ``password_scans`` and ``log_scans``, scoped to ``auth.uid()``.
2. Build ``report_data`` (a JSON-serializable snapshot of the scan summaries).
3. Render the PDF via :class:`PDFReportGenerator`.
4. Upload the PDF to the private Storage bucket via
   :class:`ReportStorageService`, which returns the object key and a signed URL.
5. Insert the ``public.reports`` row with the report ``id``, ``user_id``,
   ``title``, ``report_type``, ``storage_path`` and ``report_data``. The ``id``
   matches the Storage object key so listing can sign the same file.

Listing reads rows from ``public.reports`` scoped to the authenticated user and
attaches a fresh signed URL to every returned report.

``user_id`` always comes from the verified JWT (``auth.uid()``); it is never
accepted from the client payload. Only ``title`` (and optional ``summary`` /
``findings`` overrides) are read from the request body. All database reads and
writes run through a user-scoped client authenticated with the request's access
token, so RLS keeps every operation scoped to the authenticated user.
"""

import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone

from ..database import get_user_supabase_client
from ..errors import ServiceUnavailableError, ValidationError
from ..middleware.auth_middleware import get_current_access_token
from ..reports.pdf_generator import PDFReportGenerator
from ..reports.storage import ReportStorageService

REPORTS_TABLE = "reports"

SCAN_TABLES = (
    "website_scans",
    "email_scans",
    "password_scans",
    "log_scans",
)

DEFAULT_TITLE = "Security Audit Report"
REPORT_TYPE_PDF = "pdf"

# Number of most recent scans per category folded into a single report.
SCAN_LIMIT = 1

TITLE_MAX_LENGTH = 200


def _extract_data(result) -> list:
    """Extract the ``data`` list from a supabase ``execute()`` result."""
    if result is None:
        return []
    if isinstance(result, dict):
        data = result.get("data")
    else:
        data = getattr(result, "data", None)
    return data or []


def _validate_title(config: dict) -> str:
    """Validate and normalize the report title from the request payload."""
    title = config.get("title", DEFAULT_TITLE)
    if not isinstance(title, str) or not title.strip():
        raise ValidationError(
            "'title' must be a non-empty string", details={"field": "title"}
        )
    if len(title) > TITLE_MAX_LENGTH:
        raise ValidationError(
            f"'title' exceeds {TITLE_MAX_LENGTH} characters", details={"field": "title"}
        )
    return title.strip()


def _validate_overrides(config: dict) -> None:
    """Validate the optional ``summary`` / ``findings`` overrides."""
    summary = config.get("summary")
    if summary is not None and not isinstance(summary, str):
        raise ValidationError("'summary' must be a string", details={"field": "summary"})
    findings = config.get("findings")
    if findings is not None and not isinstance(findings, list):
        raise ValidationError("'findings' must be a list", details={"field": "findings"})


def _fetch_latest_scans(client, user_id: str) -> dict:
    """Return the most recent scan row per category, or ``None`` per category."""
    latest = {}
    for table in SCAN_TABLES:
        try:
            result = (
                client.table(table)
                .select("*")
                .eq("user_id", user_id)
                .order("created_at", desc=True)
                .limit(SCAN_LIMIT)
                .execute()
            )
        except Exception as exc:
            raise ServiceUnavailableError(
                "Scan history could not be retrieved",
                details={"table": table, "error": type(exc).__name__},
            ) from exc
        rows = _extract_data(result)
        latest[table] = rows[0] if rows else None
    return latest


def _build_summary(latest: dict) -> str:
    categories = []
    for table, label in (
        ("website_scans", "website"),
        ("email_scans", "email"),
        ("password_scans", "password"),
        ("log_scans", "log"),
    ):
        if latest.get(table):
            categories.append(label)
    if categories:
        return (
            "This report aggregates the most recent security scans on file for the "
            "account: " + ", ".join(categories) + "."
        )
    return "This report was generated with no prior scan history on file for the account."


def _build_report_data(latest: dict, title: str, report_id: str, generated_at: str, config: dict) -> dict:
    """Assemble the ``report_data`` snapshot passed to the PDF generator."""
    report_data = {
        "id": report_id,
        "title": title,
        "report_type": REPORT_TYPE_PDF,
        "generated_at": generated_at,
        "website_scan": _map_website_scan(latest.get("website_scans")),
        "email_scan": _map_email_scan(latest.get("email_scans")),
        "password_scan": _map_password_scan(latest.get("password_scans")),
        "log_scan": _map_log_scan(latest.get("log_scans")),
        "summary": _build_summary(latest),
    }
    summary = config.get("summary")
    if isinstance(summary, str) and summary.strip():
        report_data["summary"] = summary.strip()
    findings = config.get("findings")
    if findings is not None:
        report_data["findings"] = findings
    return report_data


def _map_website_scan(row):
    if not row:
        return None
    checks = row.get("findings") or []
    passed = sum(1 for c in checks if isinstance(c, dict) and c.get("status") == "passed")
    failed = sum(1 for c in checks if isinstance(c, dict) and c.get("status") == "failed")
    warnings = sum(1 for c in checks if isinstance(c, dict) and c.get("status") == "warning")
    return {
        "target": row.get("target_url"),
        "reachable": True,
        "score": row.get("security_score"),
        "grade": _grade_from_score(row.get("security_score")),
        "summary": (
            f"{passed} passed, {failed} failed, {warnings} warning(s) out of {len(checks)} checks."
        ),
        "checks": checks,
    }


def _map_email_scan(row):
    if not row:
        return None
    return {
        "subject": row.get("subject"),
        "sender_email": row.get("sender_email"),
        "predicted_label": row.get("predicted_label"),
        "risk_level": row.get("risk_level"),
        "confidence": row.get("confidence"),
        "analyzer": row.get("model_version"),
        "indicators": row.get("indicators") or [],
    }


def _map_password_scan(row):
    if not row:
        return None
    char_classes = []
    if row.get("has_lower"):
        char_classes.append("lowercase")
    if row.get("has_upper"):
        char_classes.append("uppercase")
    if row.get("has_number"):
        char_classes.append("digits")
    if row.get("has_symbol"):
        char_classes.append("special")
    return {
        "length": row.get("password_length"),
        "password_length": row.get("password_length"),
        "entropy_bits": row.get("entropy"),
        "strength_score": row.get("strength_score"),
        "strength": row.get("strength_label"),
        "strength_label": row.get("strength_label"),
        "in_common_list": row.get("breached"),
        "char_classes": char_classes,
        "recommendations": [],
    }


def _map_log_scan(row):
    if not row:
        return None
    return {
        "parsed_lines": row.get("event_count"),
        "event_count": row.get("event_count"),
        "anomalies_detected": row.get("anomaly_count"),
        "anomaly_count": row.get("anomaly_count"),
        "severity": row.get("risk_level"),
        "risk_level": row.get("risk_level"),
        "analyzer": row.get("model_version"),
        "anomalies": row.get("findings") or [],
    }


def _grade_from_score(score):
    if score is None:
        return None
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _render_pdf(report_data: dict, report_id: str) -> bytes:
    """Render the report to a PDF and return its bytes."""
    tmpdir = tempfile.mkdtemp(prefix="cybershield-report-")
    try:
        pdf_path = os.path.join(tmpdir, f"{report_id}.pdf")
        PDFReportGenerator.generate_pdf(report_data, pdf_path)
        with open(pdf_path, "rb") as handle:
            return handle.read()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


class ReportService:
    """Generate and list security reports from the user's Supabase scan data."""

    @staticmethod
    def generate_report(config: dict, user_id: str = None) -> dict:
        """Generate, upload and persist a PDF report for the authenticated user.

        Args:
            config: request payload. Only ``title`` (and the optional ``summary`` /
                ``findings`` overrides) are honored. ``user_id`` inside the payload
                is ignored.
            user_id: the authenticated user UUID (``auth.uid()``) from the verified
                JWT, never from the client payload.

        Returns:
            The persisted report row including ``signed_url``.

        Raises:
            ValidationError: for an invalid title/override or a missing user.
            ServiceUnavailableError: when Supabase or report storage is
                unavailable.
        """
        config = config or {}
        title = _validate_title(config)
        _validate_overrides(config)
        if not user_id:
            raise ValidationError(
                "A valid authenticated user is required to generate a report",
                details={"field": "user_id"},
            )

        client = get_user_supabase_client(get_current_access_token())
        if client is None:
            raise ServiceUnavailableError(
                "Report generation is unavailable (Supabase not configured)",
                code="REPORT_GENERATION_UNAVAILABLE",
            )

        report_id = str(uuid.uuid4())
        generated_at = datetime.now(timezone.utc).isoformat()
        latest = _fetch_latest_scans(client, user_id)
        report_data = _build_report_data(latest, title, report_id, generated_at, config)

        pdf_bytes = _render_pdf(report_data, report_id)
        storage = ReportStorageService.upload_pdf(pdf_bytes, user_id, report_id)

        payload = {
            "id": report_id,
            "user_id": user_id,
            "title": title,
            "report_type": REPORT_TYPE_PDF,
            "storage_path": storage["storage_path"],
            "report_data": report_data,
        }
        try:
            result = client.table(REPORTS_TABLE).insert(payload).execute()
        except Exception as exc:
            raise ServiceUnavailableError(
                "Report could not be stored",
                details={"table": REPORTS_TABLE, "error": type(exc).__name__},
            ) from exc

        row = {}
        inserted = _extract_data(result)
        if inserted:
            row.update(inserted[0])
        row.update(payload)
        row.setdefault("id", report_id)
        row.setdefault("created_at", generated_at)
        row["signed_url"] = storage["signed_url"]
        return row

    @staticmethod
    def list_reports(user_id: str = None) -> list:
        """Return the authenticated user's reports from ``public.reports``.

        Every returned report includes a freshly issued signed URL for its PDF.

        Raises:
            ValidationError: when no ``user_id`` is supplied.
            ServiceUnavailableError: when Supabase or report storage is
                unavailable.
        """
        if not user_id:
            raise ValidationError(
                "A valid authenticated user is required to list reports",
                details={"field": "user_id"},
            )
        client = get_user_supabase_client(get_current_access_token())
        if client is None:
            raise ServiceUnavailableError(
                "Reports are unavailable (Supabase not configured)",
                code="REPORTS_UNAVAILABLE",
            )
        try:
            result = (
                client.table(REPORTS_TABLE)
                .select("*")
                .eq("user_id", user_id)
                .order("created_at", desc=True)
                .execute()
            )
        except Exception as exc:
            raise ServiceUnavailableError(
                "Reports could not be retrieved",
                details={"table": REPORTS_TABLE, "error": type(exc).__name__},
            ) from exc

        reports = []
        for row in _extract_data(result):
            report = dict(row)
            report_id = report.get("id")
            if report_id:
                report["signed_url"] = ReportStorageService.get_signed_url(user_id, report_id)
            reports.append(report)
        return reports
