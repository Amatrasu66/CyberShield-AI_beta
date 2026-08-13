"""
Report storage service: Supabase Storage integration for generated PDF reports.

Uploads generated PDF files to the private ``REPORT_STORAGE_BUCKET`` bucket using
the server-only admin (secret-key) client and returns a time-limited signed URL.

Security model:
- The bucket is private; access is only ever granted through signed URLs. The
  bucket is never made public and ``get_public_url`` is never used.
- The secret-key client runs with elevated privileges and is used exclusively
  server-side; it is never exposed to the frontend. Only signed URLs cross the
  service boundary.
- Objects are namespaced under ``<user_id>/<report_id>.pdf`` and both segments
  are validated to prevent path traversal.

Failures are surfaced through the existing error system
(:class:`ServiceUnavailableError` for storage problems,
:class:`ValidationError` for invalid object keys) so callers keep the
consistent JSON error envelope.
"""

import logging

from flask import current_app

from ..database import get_supabase_admin_client
from ..errors import ServiceUnavailableError, ValidationError

logger = logging.getLogger("cybershield.reports.storage")

DEFAULT_SIGNED_URL_EXPIRES = 3600


def _valid_segment(value: str, name: str) -> str:
    """Validate a single path segment used in a storage object key.

    Rejects empty values, path separators, and ``.``/``..`` so a caller can
    never escape the user's storage namespace.
    """
    text = str(value or "").strip()
    if not text:
        raise ValidationError(f"'{name}' must be a non-empty string", details={"field": name})
    if "/" in text or "\\" in text or text in {".", ".."}:
        raise ValidationError(f"'{name}' contains invalid characters", details={"field": name})
    return text


class ReportStorageService:
    """Store generated PDF reports in the private Supabase Storage bucket."""

    @staticmethod
    def object_path(user_id: str, report_id: str) -> str:
        """Return the storage object key ``<user_id>/<report_id>.pdf``."""
        user_id = _valid_segment(user_id, "user_id")
        report_id = _valid_segment(report_id, "report_id")
        return f"{user_id}/{report_id}.pdf"

    @staticmethod
    def _resolve_config(config):
        """Resolve storage configuration and the elevated Supabase client.

        Args:
            config: explicit config mapping, or ``None`` to read from the Flask
                ``current_app`` configuration.

        Returns:
            A ``(client, bucket, expires_in)`` tuple.

        Raises:
            ServiceUnavailableError: if the bucket is unset or the admin client
                is unavailable (Supabase credentials not configured).
        """
        cfg = config if config is not None else current_app.config
        bucket = (cfg.get("REPORT_STORAGE_BUCKET") or "").strip()
        try:
            expires_in = int(cfg.get("REPORT_SIGNED_URL_EXPIRES") or DEFAULT_SIGNED_URL_EXPIRES)
        except (TypeError, ValueError):
            expires_in = DEFAULT_SIGNED_URL_EXPIRES
        if not bucket:
            raise ServiceUnavailableError(
                "Report storage bucket is not configured",
                code="STORAGE_UNAVAILABLE",
            )
        client = get_supabase_admin_client()
        if client is None:
            raise ServiceUnavailableError(
                "Report storage is unavailable (Supabase credentials not configured)",
                code="STORAGE_UNAVAILABLE",
                details={"bucket": bucket},
            )
        return client, bucket, expires_in

    @classmethod
    def _create_signed_url(cls, client, bucket: str, path: str, expires_in: int) -> str:
        """Issue a signed URL for ``path`` via the admin storage client."""
        try:
            signed = client.storage.from_(bucket).create_signed_url(path, expires_in)
        except Exception as exc:
            logger.exception("Failed to sign storage URL for %s", path)
            raise ServiceUnavailableError(
                "A signed URL could not be generated for the report PDF",
                code="STORAGE_SIGNED_URL_FAILED",
                details={"bucket": bucket, "path": path, "error": type(exc).__name__},
            ) from exc
        url = (signed or {}).get("signedURL") or (signed or {}).get("signedUrl")
        if not url:
            raise ServiceUnavailableError(
                "A signed URL could not be generated for the report PDF",
                code="STORAGE_SIGNED_URL_FAILED",
                details={"bucket": bucket, "path": path},
            )
        return url

    @classmethod
    def upload_pdf(cls, pdf_file, user_id: str, report_id: str, config=None) -> dict:
        """Upload a generated PDF and return its storage path plus signed URL.

        Args:
            pdf_file: the PDF payload; ``bytes``, a binary file-like object, or
                a path to the generated file (see ``supabase`` upload).
            user_id: the owning user UUID (``auth.uid()``).
            report_id: the report UUID.
            config: optional config mapping; defaults to ``current_app.config``.

        Returns:
            ``{"storage_path": "<user_id>/<report_id>.pdf", "signed_url": ...}``.

        Raises:
            ValidationError: for an invalid user/report id.
            ServiceUnavailableError: when storage is not configured, the upload
                fails, or a signed URL cannot be issued.
        """
        client, bucket, expires_in = cls._resolve_config(config)
        path = cls.object_path(user_id, report_id)
        try:
            client.storage.from_(bucket).upload(
                path, pdf_file, {"content-type": "application/pdf"}
            )
        except Exception as exc:
            logger.exception("Failed to upload report PDF to %s", path)
            raise ServiceUnavailableError(
                "The report PDF could not be uploaded",
                code="STORAGE_UPLOAD_FAILED",
                details={"bucket": bucket, "path": path, "error": type(exc).__name__},
            ) from exc
        signed_url = cls._create_signed_url(client, bucket, path, expires_in)
        return {"storage_path": path, "signed_url": signed_url}

    @classmethod
    def get_signed_url(cls, user_id: str, report_id: str, config=None) -> str:
        """Issue a signed URL for an already-stored report PDF.

        Args:
            user_id: the owning user UUID (``auth.uid()``).
            report_id: the report UUID.
            config: optional config mapping; defaults to ``current_app.config``.

        Returns:
            The signed access URL string.

        Raises:
            ValidationError: for an invalid user/report id.
            ServiceUnavailableError: when storage is not configured or signing
                fails.
        """
        client, bucket, expires_in = cls._resolve_config(config)
        path = cls.object_path(user_id, report_id)
        return cls._create_signed_url(client, bucket, path, expires_in)
