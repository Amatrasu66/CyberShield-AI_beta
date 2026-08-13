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

from ..database import get_user_supabase_client
from ..errors import ServiceUnavailableError
from ..middleware.auth_middleware import get_current_access_token

PROFILES_TABLE = "profiles"


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
