"""
SQL Injection Playground Service (Educational).

An isolated, in-memory demonstration of why parameterized queries prevent SQL
injection. The service NEVER executes SQL and NEVER connects to any database.
It only renders illustrative query strings for study.

The rendered queries are plain text: even though the raw input may contain
quotes or comment markers, it is transported as JSON (safely escaped) and is
never interpreted by any SQL engine.
"""

import re

from ..errors import ValidationError

SQL_META_PATTERNS = [
    ("single_quote", re.compile(r"'")),
    ("sql_comment", re.compile(r"--")),
    ("block_comment", re.compile(r"/\*")),
    ("semicolon_statement", re.compile(r";")),
    ("boolean_or", re.compile(r"'\s*OR\s*'", re.IGNORECASE)),
    ("boolean_always_true", re.compile(r"\b1\s*=\s*1\b")),
    ("union_select", re.compile(r"\bunion\b.*\bselect\b", re.IGNORECASE)),
    ("comment_bypass", re.compile(r"'?\s*--\s*$", re.IGNORECASE)),
]

# Reference payloads shown in the fixed example.
EXAMPLE_INPUT = "' OR '1'='1"
EXAMPLE_UNSAFE_OUTPUT = "Authentication bypass (all user rows returned, simulated)"
EXAMPLE_SAFE_OUTPUT = "No rows returned; the input was treated as literal data"


class SQLPlaygroundService:
    """Educational SQL injection comparison. No SQL is ever executed."""

    @staticmethod
    def run_demo(input_value: str) -> dict:
        """Compare vulnerable (concatenation) vs. parameterized handling of input."""
        unsafe_query = f"SELECT * FROM users WHERE username = '{input_value}' AND password = 'secret';"
        safe_query = (
            "SELECT * FROM users WHERE username = ? AND password = ?;  "
            "-- parameters: ('{0}', 'secret')".format(input_value)
        )
        detected = [
            name for name, pattern in SQL_META_PATTERNS if pattern.search(input_value)
        ]
        vulnerable = bool(detected)

        return {
            "demo": "login",
            "input": input_value,
            "vulnerable_pattern_detected": vulnerable,
            "detected_patterns": detected,
            "outcome": "blocked_by_parameterization",
            "unsafe_query": unsafe_query,
            "safe_query": safe_query,
            "explanations": {
                "parameterized": (
                    "The parameterized (safe) query binds the user input as a "
                    "single literal value. Even when input contains SQL metacharacters, "
                    "the database never treats them as part of the query structure."
                ),
                "security": (
                    "String concatenation ('" + input_value + "' inserted directly) "
                    "allows an attacker to rewrite the query logic, e.g. the classic "
                    "authentication bypass. Always use placeholders and bind parameters."
                ),
                "example": {
                    "input": EXAMPLE_INPUT,
                    "unsafe_result": EXAMPLE_UNSAFE_OUTPUT,
                    "safe_result": EXAMPLE_SAFE_OUTPUT,
                },
            },
        }

    @staticmethod
    def validate_input(input_value: str, max_length: int = 4096) -> str:
        """Validate the demo input (length bounds only)."""
        if not isinstance(input_value, str):
            raise ValidationError("'input' must be a string", details={"field": "input"})
        if len(input_value) > max_length:
            raise ValidationError(
                f"'input' exceeds the maximum length of {max_length} characters",
                details={"field": "input", "max_length": max_length},
            )
        return input_value
