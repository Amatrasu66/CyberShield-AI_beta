"""
Authentication Service.

Routes and validation for authentication are implemented, but actual
registration/login requires persistent storage. Persistence is provided by
Supabase in the database phase; until then these operations return a clear,
structured 501 response instead of silently pretending to succeed.

Security: passwords are validated for format only, never stored, never logged.
"""

from ..errors import FeatureUnavailableError, ValidationError
from ..utils.validators import validate_email
from ..utils.security import hash_password

UNAVAILABLE_MESSAGE = (
    "Authentication persistence requires the Supabase database integration "
    "which is planned for the next development phase."
)

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


class AuthService:
    """Auth service scaffold — functional once Supabase is wired in."""

    @staticmethod
    def register(email: str, password: str) -> dict:
        """Validate registration payload and hand off to persistence."""
        email = validate_email(email)
        _validate_password(password)

        # No persistence layer exists yet — this is validated and then refused.
        raise FeatureUnavailableError(
            UNAVAILABLE_MESSAGE,
            code="AUTH_UNAVAILABLE",
            details={"endpoint": "register", "phase": "supabase-integration"},
        )

    @staticmethod
    def login(email: str, password: str) -> dict:
        """Validate login payload and hand off to persistence."""
        email = validate_email(email)
        if not isinstance(password, str) or not password:
            raise ValidationError("'password' is required", details={"field": "password"})
        if len(password) > MAX_PASSWORD_LENGTH:
            raise ValidationError(
                f"'password' exceeds {MAX_PASSWORD_LENGTH} characters",
                details={"field": "password"},
            )

        raise FeatureUnavailableError(
            UNAVAILABLE_MESSAGE,
            code="AUTH_UNAVAILABLE",
            details={"endpoint": "login", "phase": "supabase-integration"},
        )

    @staticmethod
    def _password_hash_only(password: str) -> str:
        """Demonstrate bcrypt hashing path used once persistence exists."""
        return hash_password(password)


def _validate_password(password):
    if not isinstance(password, str):
        raise ValidationError("'password' must be a string", details={"field": "password"})
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"'password' must be at least {MIN_PASSWORD_LENGTH} characters",
            details={"field": "password"},
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValidationError(
            f"'password' exceeds {MAX_PASSWORD_LENGTH} characters",
            details={"field": "password"},
        )
