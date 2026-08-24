"""
Global exception and error handling middleware.

Converts every failure into the consistent JSON error envelope so clients never
receive raw stack traces. Internal details are logged, never leaked to clients.
"""

import logging

from flask import current_app, request

from ..errors import ApiError
from ..utils.helpers import error_response

logger = logging.getLogger("cybershield.errors")

# Keys that are safe to expose to clients; everything else is hidden
_SAFE_DETAIL_KEYS = {
    "field",
    "fields",
    "limit",
    "limit_bytes",
    "window_seconds",
    "retry_after_seconds",
    "max",
    "max_length",
    "min_length",
    "max_bytes",
    "size_bytes",
    "count",
    "port",
    "value",
    "profile",
    "type",
    "reason",
    "allowed",
    "path",
    "scheme",
}

_SENSITIVE_KEY_SUBSTRINGS = (
    "key",
    "token",
    "secret",
    "auth",
    "password",
    "jwt",
    "service_role",
    "api",
    "sql",
    "stack",
    "trace",
    "bucket",
    "table",
    "error",
)


def _sanitize_details(details):
    """Return a client-safe copy of ``details``.

    - Only allowlisted keys are kept.
    - Any key containing a sensitive substring is dropped.
    - Values are truncated to 200 chars to prevent header/row leaks.
    - Non-dict details are dropped in production (logged server-side instead).
    """
    if not isinstance(details, dict):
        return None
    sanitized = {}
    for k, v in details.items():
        if not isinstance(k, str):
            continue
        lk = k.lower()
        # Drop sensitive keys
        if any(sub in lk for sub in _SENSITIVE_KEY_SUBSTRINGS):
            # Exception: "retry_after_seconds" and "window_seconds" contain no secret but match substring check;
            # they are in _SAFE_DETAIL_KEYS so allow them explicitly
            if lk not in _SAFE_DETAIL_KEYS:
                continue
        if lk not in _SAFE_DETAIL_KEYS:
            continue
        # Keep only primitive / list primitives
        if isinstance(v, str) and len(v) > 200:
            v = v[:200] + "..."
        if isinstance(v, list):
            # Truncate and sanitize list elements
            safe_list = []
            for item in v[:20]:
                if isinstance(item, str) and len(item) > 200:
                    item = item[:200] + "..."
                if isinstance(item, (str, int, float, bool)) or item is None:
                    safe_list.append(item)
            v = safe_list
        if isinstance(v, (str, int, float, bool)) or v is None or isinstance(v, list):
            sanitized[k] = v
    return sanitized if sanitized else None


def register_error_handlers(app):
    """Register centralized JSON error handlers on the Flask app."""

    @app.errorhandler(ApiError)
    def handle_api_error(exc):
        # Log full details server-side; expose only sanitized copy
        try:
            is_prod = str(current_app.config.get("ENVIRONMENT", "")).lower() == "production"
        except Exception:
            is_prod = False
        if exc.details:
            if is_prod:
                logger.warning("ApiError %s: %s details=%s", exc.code, exc.message, exc.details)
            else:
                # In dev/testing also log for visibility
                logger.info("ApiError %s: %s details=%s", exc.code, exc.message, exc.details)
        sanitized = _sanitize_details(exc.details) if is_prod else _sanitize_details(exc.details)
        # In non-prod we still sanitize but keep safe keys; raw table/error are already dropped above,
        # so even in dev we hide sensitive internals. This satisfies the requirement to not expose
        # via API while keeping logs.
        return error_response(
            message=exc.message,
            status_code=exc.status_code,
            code=exc.code,
            details=sanitized,
        )

    @app.errorhandler(404)
    def handle_not_found(exc):
        return error_response(
            message="Resource not found",
            status_code=404,
            code="NOT_FOUND",
            details={"path": request.path},
        )

    @app.errorhandler(405)
    def handle_method_not_allowed(exc):
        return error_response(
            message="Method not allowed",
            status_code=405,
            code="METHOD_NOT_ALLOWED",
            details={"allowed": sorted(exc.valid_methods) if exc.valid_methods else None},
        )

    @app.errorhandler(400)
    def handle_bad_request(exc):
        return error_response(
            message="Request body must be valid JSON",
            status_code=400,
            code="INVALID_JSON",
        )

    @app.errorhandler(413)
    def handle_payload_too_large(exc):
        limit = app.config.get("MAX_CONTENT_LENGTH")
        return error_response(
            message="Request payload too large",
            status_code=413,
            code="PAYLOAD_TOO_LARGE",
            details={"limit_bytes": limit},
        )

    @app.errorhandler(415)
    def handle_unsupported_media_type(exc):
        return error_response(
            message="Unsupported media type; send application/json",
            status_code=415,
            code="UNSUPPORTED_MEDIA_TYPE",
        )

    @app.errorhandler(Exception)
    def handle_unexpected_error(exc):
        logger.exception("Unhandled exception: %s", exc)
        return error_response(
            message="An internal error occurred",
            status_code=500,
            code="INTERNAL_ERROR",
        )
