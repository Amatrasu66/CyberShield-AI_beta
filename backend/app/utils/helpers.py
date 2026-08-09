"""
General shared utilities.

Standardized JSON API envelope used across the whole backend:

Success:
    ``{"success": true, "message": "...", "data": {...}, "meta": {...}}``

Error:
    ``{"success": false, "message": "...", "error": {"code": "...", "details": ...}}``
"""


def success_response(data=None, message="OK", status_code=200, meta=None):
    """Build the consistent success JSON envelope.

    Returns a ``(dict, status_code)`` tuple compatible with Flask views.
    """
    payload = {
        "success": True,
        "message": message,
        "data": data,
    }
    if meta is not None:
        payload["meta"] = meta
    return payload, status_code


def error_response(message="An error occurred", status_code=400, code="BAD_REQUEST", details=None):
    """Build the consistent error JSON envelope.

    Returns a ``(dict, status_code)`` tuple compatible with Flask views.
    """
    payload = {
        "success": False,
        "message": message,
        "error": {
            "code": code,
            "details": details,
        },
    }
    return payload, status_code
