"""
Global exception and error handling middleware.

Converts every failure into the consistent JSON error envelope so clients never
receive raw stack traces. Internal details are logged, never leaked to clients.
"""

import logging

from flask import request

from ..errors import ApiError
from ..utils.helpers import error_response

logger = logging.getLogger("cybershield.errors")


def register_error_handlers(app):
    """Register centralized JSON error handlers on the Flask app."""

    @app.errorhandler(ApiError)
    def handle_api_error(exc):
        return error_response(
            message=exc.message,
            status_code=exc.status_code,
            code=exc.code,
            details=exc.details,
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
