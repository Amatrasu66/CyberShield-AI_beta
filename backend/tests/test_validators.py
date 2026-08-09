"""Tests for shared validation utilities."""

import pytest

from app.errors import ValidationError
from app.utils.validators import validate_email, validate_string


class TestValidateString:
    def test_valid_string(self):
        assert validate_string("hello", "x", 10) == "hello"

    def test_non_string_rejected(self):
        with pytest.raises(ValidationError):
            validate_string(123, "x", 10)

    def test_too_short_rejected(self):
        with pytest.raises(ValidationError):
            validate_string("ab", "x", 10, min_length=3)

    def test_too_long_rejected(self):
        with pytest.raises(ValidationError):
            validate_string("a" * 11, "x", 10)


class TestValidateEmail:
    @pytest.mark.parametrize("email", [
        "user@example.com",
        "first.last+tag@sub.example.org",
    ])
    def test_valid_emails(self, email):
        assert validate_email(email) == email

    @pytest.mark.parametrize("email", [
        "not-an-email",
        "a@b",
        "",
        "@example.com",
        "user@",
    ])
    def test_invalid_emails(self, email):
        with pytest.raises(ValidationError):
            validate_email(email)
