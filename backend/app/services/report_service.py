"""
Security Report Service.

In-memory report generation to demonstrate the API contract.

This phase:
- Reports are generated and kept only in memory for the current process.
- No persistent storage, no database, no final PDF pipeline.

Future phases:
- Persistence via a repository layer backed by Supabase.
- Optional PDF rendering via ``app/reports/pdf_generator.py`` (ReportLab).
"""

import threading
import uuid
from datetime import datetime, timezone

from ..errors import ValidationError

_lock = threading.Lock()
_reports = []


class ReportService:
    """Generate and list in-memory security reports."""

    @staticmethod
    def generate_report(config: dict, user_id: str = None) -> dict:
        """Build an in-memory report from a configuration payload.

        ``user_id`` is the authenticated user UUID (``auth.uid()``) taken from
        the verified JWT, never from the client payload. It is stored on the
        report so results can be scoped per user.
        """
        title = config.get("title", "Security Audit Report")
        if not isinstance(title, str) or not title.strip():
            raise ValidationError("'title' must be a non-empty string", details={"field": "title"})
        if len(title) > 200:
            raise ValidationError("'title' exceeds 200 characters", details={"field": "title"})

        findings = config.get("findings")
        if findings is None:
            findings = []
        if not isinstance(findings, list):
            raise ValidationError("'findings' must be a list", details={"field": "findings"})

        report = {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "title": title.strip(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "finding_count": len(findings),
            "findings": findings,
            "summary": config.get("summary") or (
                f"Report '{title}' generated with {len(findings)} finding(s)."
            ),
            "storage": "in-memory",
            "persistence": "pending-supabase",
        }

        with _lock:
            _reports.append(report)
        return report

    @staticmethod
    def list_reports(user_id: str = None) -> list:
        """Return reports generated during the current process lifetime.

        When ``user_id`` is given, only that user's reports are returned.
        """
        with _lock:
            if user_id is None:
                return list(_reports)
            return [r for r in _reports if r.get("user_id") == user_id]

    @staticmethod
    def clear_reports():
        """Reset the in-memory store (used by tests)."""
        with _lock:
            _reports.clear()
