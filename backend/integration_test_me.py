"""
Temporary JWT diagnostic (integration_test_me.py).

Signs in the CyberShield test user against Supabase Auth, decodes the issued
access token IN MEMORY (no verification, no persistence), and prints only the
non-secret header/claim fields needed to compare with the backend's current JWT
verification settings.

Never prints the JWT, the password, API keys, or the token signature.
No production code is imported beyond read-only configuration defaults.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import jwt

# Make the `app` package importable when run from anywhere.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(Path(__file__).resolve().parent / ".env")

from app.config.settings import Config  # noqa: E402


def _redacted(value: str) -> str:
    """Return a safe display form for a config value (never a secret)."""
    return value or "(not set / derived)"


def _decode_header(token: str) -> dict:
    """Unverified header decode: returns ``alg`` and ``kid`` only."""
    header = jwt.get_unverified_header(token)
    return {"alg": header.get("alg"), "kid": header.get("kid")}


def _decode_claims(token: str) -> dict:
    """Unverified claims decode. Signature/verification checks are off."""
    return jwt.decode(
        token,
        options={
            "verify_signature": False,
            "verify_aud": False,
            "verify_iss": False,
            "verify_exp": False,
            "verify_iat": False,
            "verify_nbf": False,
            "require": [],
        },
    )


def _exp_status(exp):
    """Return whether ``exp`` is still valid plus the remaining time."""
    if not isinstance(exp, (int, float)):
        return "present" if exp is not None else "missing", "n/a"
    now = datetime.now(timezone.utc)
    exp_dt = datetime.fromtimestamp(float(exp), timezone.utc)
    remaining = int((exp_dt - now).total_seconds())
    valid = remaining > 0
    if not valid:
        return "expired", f"{abs(remaining)}s ago"
    return "valid", f"{remaining // 60}m {remaining % 60}s remaining"


def main() -> int:
    cfg = Config

    supabase_url = (cfg.SUPABASE_URL or "").strip()
    if not supabase_url:
        print("[ERROR] SUPABASE_URL is not set in .env")
        return 2

    expected_issuer = (cfg.SUPABASE_JWT_ISSUER or "").strip() or f"{supabase_url}/auth/v1"
    expected_alg = cfg.SUPABASE_JWT_ALGORITHM
    expected_aud = cfg.SUPABASE_JWT_AUDIENCE

    print("=== Step 1: Sign in the CyberShield test user ===")
    import os

    email = os.environ.get("CS_TEST_USER_EMAIL", "").strip()
    password = os.environ.get("CS_TEST_USER_PASSWORD", "")
    if not email:
        email = input("Test user email: ").strip()
    if not email:
        print("[ERROR] Email is required")
        return 2
    if not password:
        import getpass

        password = getpass.getpass("Test user password: ")
    if not password:
        print("[ERROR] Password is required")
        return 2

    from app.database.supabase_client import _build_client
    from app.database.supabase_client import _publishable_key

    client = _build_client(supabase_url, _publishable_key())
    if client is None:
        print("[ERROR] Supabase client could not be built (missing key?)")
        return 2

    try:
        auth_response = client.auth.sign_in_with_password(
            {"email": email, "password": password}
        )
    except Exception as exc:  # noqa: BLE001 - diagnostic surface
        print(f"[ERROR] Sign-in failed: {type(exc).__name__}: {exc}")
        return 1

    access_token = getattr(
        getattr(auth_response, "session", None), "access_token", None
    )
    if not access_token:
        print("[ERROR] No access token returned by Supabase Auth")
        return 1

    print("[OK] Signed in as the CyberShield test user (token obtained in memory).")

    print("\n=== Step 2: Decode the test-user access token (unverified, in memory) ===")
    header = _decode_header(access_token)
    claims = _decode_claims(access_token)

    exp_status, remaining = _exp_status(claims.get("exp"))
    print(f"alg : {header.get('alg')}")
    print(f"kid : {header.get('kid')}")
    print(f"iss : {claims.get('iss')}")
    print(f"aud : {claims.get('aud')}")
    print(f"sub : {claims.get('sub')}")
    print(f"exp : {exp_status} ({remaining})")

    print("\n=== Step 3: Expected issuer from backend configuration ===")
    print(f"expected iss (SUPABASE_JWT_ISSUER or {supabase_url}/auth/v1) : {expected_issuer}")
    print(f"expected alg (SUPABASE_JWT_ALGORITHM)                         : {expected_alg}")
    print(f"expected aud (SUPABASE_JWT_AUDIENCE)                          : {expected_aud}")

    print("\n=== Step 4: Comparison ===")
    matches = {
        "alg": (claims.get("alg") if False else header.get("alg")) == expected_alg,
        "iss": claims.get("iss") == expected_issuer,
        "aud": claims.get("aud") == expected_aud,
    }
    for name, ok in matches.items():
        print(f"{name:>4}: {'MATCH' if ok else 'MISMATCH'}")
    print(
        "exp: "
        + ("VALID (still valid)" if exp_status == "valid" else f"NOT VALID ({exp_status})")
    )
    if not all(matches.values()):
        print("\n[NOTE] One or more claims do not match the backend verification settings.")
        print("       This explains why the backend rejects the token (401).")

    # Clean up: sign the session out without printing anything.
    try:
        client.auth.sign_out()
    except Exception:  # noqa: BLE001 - best effort, diagnostic only
        pass
    return 0 if all(matches.values()) and exp_status == "valid" else 1


if __name__ == "__main__":
    sys.exit(main())
