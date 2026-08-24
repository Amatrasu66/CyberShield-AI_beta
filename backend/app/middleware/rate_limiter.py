"""
Process-local sliding-window rate limiter for authenticated scanner endpoints.

Uses an in-memory dict keyed by (user_id, endpoint) storing deque of request
timestamps. No Redis; suitable for single-process dev and for Render's
single-instance starter tier, but limits are per-process when scaled to
multiple Gunicorn workers or instances — see docs.

Limits are enforced server-side via ``@require_auth`` identity and are not
controllable by the frontend. Exceeded requests receive a consistent
``{success:false, error:{code:RATE_LIMIT_EXCEEDED}}`` envelope with HTTP 429.
"""

from __future__ import annotations

import time
from collections import deque, defaultdict
from functools import wraps
from threading import Lock
from typing import Callable

from flask import request, current_app, has_request_context

from ..errors import ApiError

# Global in-memory store: key -> deque[timestamp]
_store: dict[str, deque] = defaultdict(deque)
_lock = Lock()


def _get_limit_config(key: str) -> tuple[int, int]:
    """Return (limit, window_seconds) for a limiter key from Flask config."""
    mapping = {
        "port_scan": ("RATE_LIMIT_PORT_SCAN", "RATE_LIMIT_PORT_SCAN_WINDOW"),
        "ip_reputation": ("RATE_LIMIT_IP_REPUTATION", "RATE_LIMIT_IP_REPUTATION_WINDOW"),
    }
    limit_key, window_key = mapping.get(key, (None, None))
    if limit_key is None:
        return 60, 60  # safe default
    try:
        limit = int(current_app.config.get(limit_key, 60))
        window = int(current_app.config.get(window_key, 60))
    except RuntimeError:
        # Outside app context (e.g., import time) — use defaults
        limit, window = 60, 60
    except Exception:
        limit, window = 60, 60
    return max(1, limit), max(1, window)


def _resolve_user_key() -> str:
    """Resolve rate-limit identity: authenticated user_id else remote IP."""
    # Prefer authenticated user; fall back to remote addr for unauth paths
    try:
        if has_request_context():
            claims = getattr(request, "auth", None)
            if claims and claims.get("sub"):
                return f"user:{claims['sub']}"
            # Try X-Forwarded-For behind Render proxy
            forwarded = request.headers.get("X-Forwarded-For", "")
            if forwarded:
                return f"ip:{forwarded.split(',')[0].strip()}"
            return f"ip:{request.remote_addr or 'unknown'}"
    except Exception:
        pass
    return "ip:unknown"


def _check_and_record(key: str, limit: int, window: int) -> tuple[bool, int]:
    """Check window and record request. Returns (allowed, retry_after_seconds)."""
    now = time.monotonic()
    cutoff = now - window
    with _lock:
        dq = _store[key]
        # Evict expired
        while dq and dq[0] <= cutoff:
            dq.popleft()
        if len(dq) >= limit:
            # Retry after oldest entry expires
            retry_after = int(dq[0] + window - now) + 1
            return False, max(1, retry_after)
        dq.append(now)
        return True, 0


def rate_limit(limiter_key: str = "default", limit: int | None = None, window: int | None = None):
    """Decorator enforcing a sliding-window rate limit per authenticated user.

    Args:
        limiter_key: logical bucket name (e.g., "port_scan"). When ``limit``
            or ``window`` are None the values are read from Flask config
            ``RATE_LIMIT_<KEY>`` / ``RATE_LIMIT_<KEY>_WINDOW``.
        limit: max requests per window (overrides config if provided).
        window: window in seconds (overrides config if provided).

    Raises:
        ApiError 429 RATE_LIMIT_EXCEEDED when exceeded.
    """

    def decorator(f: Callable):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Check if rate limiting globally disabled
            try:
                if not current_app.config.get("RATE_LIMIT_ENABLED", True):
                    return f(*args, **kwargs)
            except RuntimeError:
                return f(*args, **kwargs)

            # Resolve limit/window: explicit args override config
            eff_limit, eff_window = limit, window
            if eff_limit is None or eff_window is None:
                cfg_limit, cfg_window = _get_limit_config(limiter_key)
                eff_limit = eff_limit if eff_limit is not None else cfg_limit
                eff_window = eff_window if eff_window is not None else cfg_window

            identity = _resolve_user_key()
            store_key = f"{limiter_key}:{identity}"

            allowed, retry_after = _check_and_record(store_key, eff_limit, eff_window)
            if not allowed:
                raise ApiError(
                    "Rate limit exceeded. Please try again shortly.",
                    status_code=429,
                    code="RATE_LIMIT_EXCEEDED",
                    details={"retry_after_seconds": retry_after, "limit": eff_limit, "window_seconds": eff_window},
                )
            return f(*args, **kwargs)

        return wrapped

    return decorator


def clear_rate_limit_store():
    """Clear all rate-limit state (used in tests)."""
    with _lock:
        _store.clear()


def _rate_limit_headers(limit: int, window: int, remaining: int):
    """Helper to build standard headers (not yet used in responses)."""
    return {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Window": str(window),
        "X-RateLimit-Remaining": str(max(0, remaining)),
    }
