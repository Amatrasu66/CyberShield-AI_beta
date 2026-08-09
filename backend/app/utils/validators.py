"""
Input validation and sanitization helpers.

Every external input reaching the backend is validated here before it reaches
business logic. Validators are pure and deterministic so they are unit-testable.
"""

import ipaddress
import re

from flask import current_app, request

from ..errors import PayloadTooLargeError, ValidationError

URL_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^\s]+$")
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def require_json():
    """Ensure the current request carries a JSON body and return it.

    Raises a :class:`ValidationError` with a consistent envelope otherwise.
    """
    from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

    try:
        data = request.get_json(silent=False, force=False)
    except (BadRequest, RequestEntityTooLarge):
        raise
    except Exception:
        raise ValidationError("Request body must be valid JSON", details={"field": "body"})
    if not isinstance(data, dict):
        raise ValidationError("Request body must be a JSON object", details={"field": "body"})
    return data


def check_payload_size_limit(size: int, limit_key: str = "MAX_CONTENT_LENGTH"):
    """Raise if the given size exceeds the configured limit."""
    limit = int(current_app.config.get(limit_key, 1_000_000) or 1_000_000)
    if size is not None and size > limit:
        raise PayloadTooLargeError(
            f"Input exceeds the configured limit of {limit} characters",
            details={"limit": limit},
        )


def validate_string(value, field: str, max_length: int, min_length: int = 0):
    """Validate that ``value`` is a string within length bounds."""
    if not isinstance(value, str):
        raise ValidationError(
            f"'{field}' must be a string", details={"field": field, "type": type(value).__name__}
        )
    if len(value) < min_length:
        raise ValidationError(
            f"'{field}' must be at least {min_length} characters",
            details={"field": field, "min_length": min_length},
        )
    if len(value) > max_length:
        raise ValidationError(
            f"'{field}' exceeds the maximum length of {max_length} characters",
            details={"field": field, "max_length": max_length},
        )
    return value


def validate_url(url: str, max_length: int = 2048) -> str:
    """Validate a URL suitable for the educational scanner.

    Only ``http``/``https`` schemes with a real hostname are accepted. URLs
    embedding credentials are rejected. Returns the normalized URL.
    """
    from urllib.parse import urlsplit

    validate_string(url, "url", max_length)
    url = url.strip()

    if not URL_REGEX.match(url):
        raise ValidationError(
            "URL must use the http:// or https:// scheme",
            details={"field": "url"},
        )

    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValidationError(
            "Only http:// and https:// URLs are allowed",
            details={"field": "url", "scheme": parsed.scheme},
        )
    if not parsed.hostname:
        raise ValidationError("URL must include a hostname", details={"field": "url"})
    if parsed.username or parsed.password:
        raise ValidationError(
            "URLs must not embed credentials", details={"field": "url"}
        )
    try:
        if parsed.port is not None and not (0 < parsed.port < 65536):
            raise ValidationError("URL contains an invalid port", details={"field": "url"})
    except ValueError:
        raise ValidationError("URL contains an invalid port", details={"field": "url"})

    return url


def is_private_host(url: str) -> bool:
    """Return True if the URL hostname resolves to a private/reserved address.

    Used to prevent the educational scanner from being abused as an SSRF tool.
    Hostnames that cannot be resolved return False so the scanner's own
    connection-error handling reports an unreachable target.
    """
    import socket

    from urllib.parse import urlsplit

    hostname = urlsplit(url).hostname
    if not hostname:
        return True
    try:
        info = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for addr in info:
        ip = ipaddress.ip_address(addr[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return True
    return False


def validate_email(email: str) -> str:
    """Validate an email address format."""
    validate_string(email, "email", 254)
    email = email.strip()
    if not EMAIL_REGEX.match(email):
        raise ValidationError(
            "Invalid email address format", details={"field": "email"}
        )
    return email


def validate_password_input(password, max_length: int = 4096) -> str:
    """Validate the password submitted for analysis (format only).

    The password is never stored and never logged.
    """
    return validate_string(password, "password", max_length)
