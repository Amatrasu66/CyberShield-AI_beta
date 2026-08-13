"""
Application configuration.

Loads environment variables (with optional .env support) and exposes a single
Config object consumed by the Flask application factory.

Secrets are never hardcoded. Default values are only safe development
fallbacks and MUST be overridden in production.
"""

import os

from dotenv import load_dotenv

load_dotenv()


def _env_bool(name: str, default: bool = False) -> bool:
    """Parse a boolean environment variable safely."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    """Parse an integer environment variable safely."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def _env_list(name: str, default: str) -> list:
    """Parse a comma separated list environment variable."""
    raw = os.environ.get(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


class Config:
    """Base application configuration."""

    # --- App identity ---------------------------------------------------
    APP_NAME = os.environ.get("APP_NAME", "CyberShield AI API")
    API_VERSION = os.environ.get("API_VERSION", "1.0")
    API_URL_PREFIX = os.environ.get("API_URL_PREFIX", "/api")
    ENVIRONMENT = os.environ.get("APP_ENV", os.environ.get("FLASK_ENV", "development"))
    DEBUG = _env_bool("FLASK_DEBUG", ENVIRONMENT in {"development", "debug"})
    TESTING = ENVIRONMENT == "testing"

    # --- Security -------------------------------------------------------
    # Production deployments MUST set SECRET_KEY via the environment.
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-secret-key-change-me")
    # Keep submitted data small: 1 MB request body ceiling.
    MAX_CONTENT_LENGTH = _env_int("MAX_CONTENT_LENGTH", 1_000_000)
    JWT_EXPIRATION_MINUTES = _env_int("JWT_EXPIRATION_MINUTES", 60)
    JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")

    # --- CORS -----------------------------------------------------------
    # "*" is a development convenience; restrict in production.
    CORS_ORIGINS = _env_list("CORS_ORIGINS", "*")
    CORS_SUPPORTS_CREDENTIALS = _env_bool("CORS_SUPPORTS_CREDENTIALS", False)

    # --- Logging ---------------------------------------------------------
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    REQUEST_LOG_ENABLED = _env_bool("REQUEST_LOG_ENABLED", True)

    # --- Scanner ----------------------------------------------------------
    SCANNER_TIMEOUT = _env_int("SCANNER_TIMEOUT", 10)
    SCANNER_MAX_RESPONSE_SIZE = _env_int("SCANNER_MAX_RESPONSE_SIZE", 512_000)
    SCANNER_MAX_REDIRECTS = _env_int("SCANNER_MAX_REDIRECTS", 5)
    # When False (default) targets resolving to private/loopback addresses are
    # refused to prevent SSRF abuse of the educational scanner.
    SCANNER_ALLOW_PRIVATE_ADDRESSES = _env_bool("SCANNER_ALLOW_PRIVATE_ADDRESSES", False)
    SCANNER_USER_AGENT = os.environ.get(
        "SCANNER_USER_AGENT", "CyberShieldAI-Scanner/1.0 (educational assessment)"
    )

    # --- Input limits -----------------------------------------------------
    PASSWORD_MAX_LENGTH = _env_int("PASSWORD_MAX_LENGTH", 4096)
    EMAIL_MAX_LENGTH = _env_int("EMAIL_MAX_LENGTH", 50_000)
    LOG_MAX_LENGTH = _env_int("LOG_MAX_LENGTH", 500_000)
    LOG_MAX_LINES = _env_int("LOG_MAX_LINES", 10_000)
    CRYPTO_MAX_INPUT_LENGTH = _env_int("CRYPTO_MAX_INPUT_LENGTH", 100_000)
    URL_MAX_LENGTH = _env_int("URL_MAX_LENGTH", 2048)

    # --- Supabase (PostgreSQL database) ------------------------------------
    # From the Supabase dashboard: Project Settings > API Keys.
    SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
    # Legacy single key. Kept only as a last-resort fallback for the
    # publishable key on existing deployments.
    SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
    # Legacy low-privilege key. Backward-compatible fallback for the
    # publishable key.
    SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
    # Legacy elevated key. Backward-compatible fallback for the secret key.
    SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    # Low-privilege publishable key for the default client (safe for frontend
    # use; access is constrained by RLS). Replaces SUPABASE_ANON_KEY.
    SUPABASE_PUBLISHABLE_KEY = os.environ.get(
        "SUPABASE_PUBLISHABLE_KEY", SUPABASE_ANON_KEY or SUPABASE_KEY
    )
    # Elevated secret key for trusted server-side operations only; bypasses
    # RLS. Replaces SUPABASE_SERVICE_ROLE_KEY.
    # NEVER expose this key to the frontend or in client-side code.
    SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY", SUPABASE_SERVICE_ROLE_KEY)

    # --- Supabase JWT verification (auth) --------------------------------
    # Access tokens are signed by Supabase Auth with RS256 and published keys
    # via the project JWKS endpoint. The endpoint and the expected token claims
    # are derived from SUPABASE_URL unless explicitly overridden.
    SUPABASE_JWT_ALGORITHM = os.environ.get("SUPABASE_JWT_ALGORITHM", "RS256")
    # Supabase sets aud="authenticated" on access tokens issued to signed-in
    # users.
    SUPABASE_JWT_AUDIENCE = os.environ.get("SUPABASE_JWT_AUDIENCE", "authenticated")
    # Issuer override; derived as "{SUPABASE_URL}/auth/v1" when left empty.
    SUPABASE_JWT_ISSUER = os.environ.get("SUPABASE_JWT_ISSUER", "")
    # JWKS endpoint override; derived as "{SUPABASE_URL}/auth/v1/.well-known/jwks.json"
    # when left empty.
    SUPABASE_JWKS_URL = os.environ.get("SUPABASE_JWKS_URL", "")

    # --- Reports (PDF generation) ----------------------------------------
    # Private Supabase Storage bucket where generated PDF reports are stored.
    REPORT_STORAGE_BUCKET = os.environ.get("REPORT_STORAGE_BUCKET", "report-pdfs")
    # Lifetime (in seconds) of signed access URLs issued for report PDFs.
    REPORT_SIGNED_URL_EXPIRES = _env_int("REPORT_SIGNED_URL_EXPIRES", 3600)

    # --- Future: ML model paths (reserved, not used in this phase) -------
    PHISHING_MODEL_PATH = os.environ.get("PHISHING_MODEL_PATH", "../models/phishing_model.pkl")
    LOG_MODEL_PATH = os.environ.get("LOG_MODEL_PATH", "../models/log_analyzer.pkl")

    @classmethod
    def as_flask_mapping(cls) -> dict:
        """Return configuration as a plain dict for Flask.

        Walks the MRO so subclass overrides merge on top of base values.
        """
        mapping = {}
        for klass in reversed(cls.__mro__):
            for key, value in vars(klass).items():
                if key.startswith("_") or callable(value):
                    continue
                mapping[key] = value
        return mapping


def get_config() -> Config:
    """Return the application Config class (extension point for subclasses)."""
    return Config
