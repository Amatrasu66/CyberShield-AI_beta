"""Tests for security utilities (bcrypt hashing and JWT helpers)."""

import pytest

from app.errors import UnauthorizedError
from app.utils.security import create_access_token, decode_token, hash_password, verify_password


class TestPasswordHashing:
    def test_hash_and_verify_round_trip(self):
        hashed = hash_password("S3cr3t-Pass!")
        assert hashed != "S3cr3t-Pass!"
        assert verify_password("S3cr3t-Pass!", hashed) is True

    def test_wrong_password_rejected(self):
        hashed = hash_password("correct")
        assert verify_password("wrong", hashed) is False

    def test_hashes_are_salted(self):
        assert hash_password("same") != hash_password("same")


class TestJWT:
    def test_token_round_trip(self, app):
        token = create_access_token("user-123")
        claims = decode_token(token)
        assert claims["sub"] == "user-123"

    def test_invalid_token_rejected(self, app):
        with pytest.raises(UnauthorizedError):
            decode_token("not.a.jwt")

    def test_tampered_token_rejected(self, app):
        token = create_access_token("user-123")
        with pytest.raises(UnauthorizedError):
            decode_token(token[:-1] + ("A" if token[-1] != "A" else "B"))
