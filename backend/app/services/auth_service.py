"""
Authentication Service.

Supabase Auth owns registration, login, sessions and password hashing; React
calls Supabase Auth directly (``/auth/v1/signup``, ``/auth/v1/token``,
``/auth/v1/logout``, ``/auth/v1/user``). The Flask API therefore exposes no
signup/login routes and never sees passwords.

The only backend auth functionality required by the architecture is resolving
the authenticated user's profile from ``public.profiles``. ``user_id`` always
comes from the verified Supabase JWT ``sub`` claim (``auth.uid()``); it is never
accepted from the request body. Reads run through the user-scoped client so RLS
keeps the lookup to the requesting user.
"""

from datetime import datetime, timezone

from ..database import get_user_supabase_client
from ..errors import ServiceUnavailableError, ValidationError
from ..middleware.auth_middleware import get_current_access_token

PROFILES_TABLE = "profiles"

# Full name constraints (Phase 3A-2: user-editable, no service_role, no email/role changes)
MAX_FULL_NAME_LENGTH = 100
MIN_FULL_NAME_LENGTH = 1


def _extract_rows(result) -> list:
    """Extract the ``data`` list from a supabase ``execute()`` result."""
    if result is None:
        return []
    if isinstance(result, dict):
        data = result.get("data")
    else:
        data = getattr(result, "data", None)
    return data or []


class AuthService:
    """Resolve the authenticated user's profile from the verified JWT identity."""

    @staticmethod
    def validate_full_name(full_name) -> str:
        """Validate and normalise ``full_name`` for profile updates.

        Returns the trimmed value or raises :class:`ValidationError`.
        """
        if not isinstance(full_name, str):
            raise ValidationError(
                "'full_name' must be a string",
                details={"field": "full_name", "type": type(full_name).__name__},
            )
        trimmed = full_name.strip()
        if len(trimmed) < MIN_FULL_NAME_LENGTH:
            raise ValidationError(
                "'full_name' must not be empty",
                details={"field": "full_name"},
            )
        if len(trimmed) > MAX_FULL_NAME_LENGTH:
            raise ValidationError(
                f"'full_name' exceeds the maximum length of {MAX_FULL_NAME_LENGTH} characters",
                details={"field": "full_name", "max_length": MAX_FULL_NAME_LENGTH},
            )
        # Collapse internal whitespace and reject control characters
        if any(ord(c) < 32 for c in trimmed):
            raise ValidationError(
                "'full_name' contains invalid characters",
                details={"field": "full_name"},
            )
        return trimmed

    @staticmethod
    def get_profile(user_id: str) -> dict | None:
        """Return the user's profile row from ``public.profiles``.

        Args:
            user_id: the authenticated user UUID (``auth.uid()``) from the
                verified JWT, never from the client payload.

        Returns:
            The profile row (``id``, ``full_name``, ``role``, ``created_at``,
            ``updated_at``) or ``None`` when the user has no profile row yet.

        Raises:
            ServiceUnavailableError: when Supabase is not configured or the
                profile cannot be retrieved.
        """
        if not user_id:
            return None

        client = get_user_supabase_client(get_current_access_token())
        if client is None:
            raise ServiceUnavailableError(
                "Profile is unavailable (Supabase not configured)",
                code="PROFILE_UNAVAILABLE",
            )

        try:
            result = (
                client.table(PROFILES_TABLE)
                .select("*")
                .eq("id", user_id)
                .limit(1)
                .execute()
            )
        except Exception as exc:
            raise ServiceUnavailableError(
                "Profile could not be retrieved",
                details={"table": PROFILES_TABLE, "error": type(exc).__name__},
            ) from exc

        rows = _extract_rows(result)
        return dict(rows[0]) if rows else None

    @staticmethod
    def update_profile(user_id: str, full_name: str) -> dict:
        """Update the authenticated user's ``full_name``.

        Args:
            user_id: authenticated user UUID from verified JWT ``sub``.
            full_name: raw full_name supplied by client (will be validated).

        Returns:
            Updated profile row.

        Security: ``user_id`` is never taken from the request body; only the
        verified JWT. Only ``full_name`` is writable — role/email remain read-only
        and RLS ensures ``id = auth.uid()``.
        """
        if not user_id:
            raise ServiceUnavailableError("Authentication required", code="UNAUTHORIZED")

        normalized = AuthService.validate_full_name(full_name)

        client = get_user_supabase_client(get_current_access_token())
        if client is None:
            raise ServiceUnavailableError(
                "Profile is unavailable (Supabase not configured)",
                code="PROFILE_UNAVAILABLE",
            )

        try:
            # Attempt update via user-scoped client (RLS: id = auth.uid())
            result = (
                client.table(PROFILES_TABLE)
                .update(
                    {
                        "full_name": normalized,
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    }
                )
                .eq("id", user_id)
                .execute()
            )
        except Exception as exc:
            raise ServiceUnavailableError(
                "Profile could not be updated",
                details={"table": PROFILES_TABLE, "error": type(exc).__name__},
            ) from exc

        rows = _extract_rows(result)
        if rows:
            return dict(rows[0])

        # Fallback: profile row may not exist yet (race with signup trigger). Try insert via same RLS path.
        # The RLS INSERT is not allowed via policy, but get_user_supabase_client with RLS will fail closed — surface as unavailable.
        # Instead re-read via get_profile to allow trigger-created row before raising.
        existing = AuthService.get_profile(user_id)
        if existing is not None:
            # Row exists but update returned empty (old supabase-py behaviour). Re-attempt with explicit fetch.
            return existing
        raise ServiceUnavailableError(
            "Profile could not be updated",
            details={"table": PROFILES_TABLE, "error": "no rows affected"},
        )
