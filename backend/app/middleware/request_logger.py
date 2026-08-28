"""
Request logging and HTTP security header middleware.

- Request logging records method, path, and status without logging bodies
  (bodies may contain passwords, emails, or other sensitive content).
- Security headers harden HTTP responses.
"""

import logging
import time

from flask import request

logger = logging.getLogger("cybershield.request")

# Headers applied to every response. Kept intentionally strict but safe for
# browser clients (API responses only; served through the Vite proxy).
# HSTS is also set here; Render may add its own HSTS at the edge but
# including it at the app layer ensures direct header verification passes.
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


def register_request_logging(app):
    """Log request method, path and status code (never bodies)."""

    @app.before_request
    def _start_timer():
        request._cybershield_start_time = time.perf_counter()

    @app.after_request
    def _log_request(response):
        if app.config.get("REQUEST_LOG_ENABLED", True):
            duration_ms = (time.perf_counter() - request._cybershield_start_time) * 1000
            logger.info(
                "%s %s -> %s (%.1f ms)",
                request.method,
                request.path,
                response.status_code,
                duration_ms,
            )
        return response


def register_security_headers(app):
    """Attach hardened security headers to every response."""

    @app.after_request
    def _apply_security_headers(response):
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        return response
