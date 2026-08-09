"""
Password Strength Analyzer Service.

Computes deterministic, non-ML security characteristics for a submitted
password: length, character classes, entropy estimate, strength classification,
crack-time estimate, and actionable recommendations.

Security guarantees:
- The password is never stored anywhere.
- The password is never logged.
- Only aggregate characteristics are returned.
"""

import math
import re
import string

# Charset sizes used for the pool-based entropy estimate.
POOL_SIZES = {
    "lowercase": 26,
    "uppercase": 26,
    "digits": 10,
    "special": 33,
}

# Assumed offline attack rate used only for an educational crack-time estimate.
GUESSES_PER_SECOND = 10_000_000_000

COMMON_WEAK_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123",
    "password1", "letmein", "admin", "welcome", "monkey", "dragon",
    "1234", "12345", "111111", "iloveyou", "sunshine", "princess",
    "football", "baseball", "superman", "trustno1", "123123",
}

SEQUENCE_PATTERNS = [
    re.compile(r"(?:012|123|234|345|456|567|678|789|890|098|987|876|765|654|543|432|321|210)"),
    re.compile(r"(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)"),
    re.compile(r"(?:zyx|yxw|xwv|wvu|vut|uts|tsr|srq|rqp|qpo|pon|onm|nml|mlk|kjh|jih|ihg|hgf|gfe|fed|edc|dcb|cba)"),
    re.compile(r"qwerty|asdfgh|zxcvbn|qwertyuiop|asdf|zxcv"),
]

REPEATED_RUN_REGEX = re.compile(r"(.)\1{2,}")


class PasswordService:
    """Deterministic password strength analysis (no ML, no storage)."""

    @staticmethod
    def analyze_password(password: str) -> dict:
        """Analyze a password and return its security characteristics.

        ``password`` is used only for computation and discarded afterwards.
        """
        analysis = {
            "length": len(password),
            "char_classes": _character_classes(password),
            "uppercase": _has_class(password, "uppercase"),
            "lowercase": _has_class(password, "lowercase"),
            "digits": _has_class(password, "digits"),
            "special": _has_class(password, "special"),
            "classes_used": len(_character_classes(password)),
            "entropy_bits": _entropy_bits(password),
            "crack_time_estimate": _crack_time_category(password),
            "in_common_list": password.lower() in COMMON_WEAK_PASSWORDS,
            "strength_score": None,
            "strength": None,
            "recommendations": [],
        }

        score = _strength_score(password, analysis)
        analysis["strength_score"] = score
        analysis["strength"] = _rating(score)
        analysis["recommendations"] = _recommendations(password, analysis, score)

        # Order recommendations from most to least impactful.
        analysis["recommendations"] = sorted(
            analysis["recommendations"], key=lambda r: r.get("priority", 99)
        )
        return analysis


def _character_classes(password: str) -> list:
    classes = []
    if _has_class(password, "lowercase"):
        classes.append("lowercase")
    if _has_class(password, "uppercase"):
        classes.append("uppercase")
    if _has_class(password, "digits"):
        classes.append("digits")
    if _has_class(password, "special"):
        classes.append("special")
    return classes


def _has_class(password: str, kind: str) -> bool:
    if kind == "lowercase":
        return any(c in string.ascii_lowercase for c in password)
    if kind == "uppercase":
        return any(c in string.ascii_uppercase for c in password)
    if kind == "digits":
        return any(c in string.digits for c in password)
    # "special" = any non-alphanumeric, non-whitespace character.
    return any((not c.isalnum()) and (not c.isspace()) for c in password)


def _pool_size(password: str) -> int:
    return sum(POOL_SIZES[c] for c in _character_classes(password))


def _entropy_bits(password: str) -> float:
    """Pool-based entropy estimate in bits."""
    pool = _pool_size(password)
    if pool == 0 or not password:
        return 0.0
    return round(len(password) * math.log2(pool), 2)


def _crack_time_category(password: str) -> str:
    """Educational crack-time category based on the entropy estimate."""
    bits = _entropy_bits(password)
    if bits <= 0:
        return "instantly"
    seconds = (2 ** bits) / GUESSES_PER_SECOND
    if seconds < 1:
        return "instantly"
    if seconds < 60:
        return "seconds"
    if seconds < 3600:
        return "minutes"
    if seconds < 86400:
        return "hours"
    if seconds < 86400 * 30:
        return "days"
    if seconds < 86400 * 365:
        return "months"
    if seconds < 86400 * 365 * 100:
        return "years"
    return "centuries"


def _detect_sequences(password: str) -> bool:
    lowered = password.lower()
    return any(pattern.search(lowered) for pattern in SEQUENCE_PATTERNS)


def _has_repeated_run(password: str) -> bool:
    return bool(REPEATED_RUN_REGEX.search(password))


def _strength_score(password: str, analysis: dict) -> int:
    """Return a 0-100 deterministic strength score."""
    length = analysis["length"]
    classes = analysis["classes_used"]

    score = 0
    # Length: up to 30 points (20+ characters maxes out this component).
    score += min(30, int(length * 1.5))
    # Variety: 10 points per extra character class beyond the first (max 30).
    score += min(30, max(0, classes - 1) * 10)
    # Entropy bonus.
    bits = analysis["entropy_bits"]
    if bits >= 80:
        score += 25
    elif bits >= 60:
        score += 20
    elif bits >= 40:
        score += 15
    elif bits >= 28:
        score += 10
    # Bonus for combining adequate length with multiple character classes.
    if length >= 12 and classes >= 3:
        score += 10

    # Penalties.
    if length < 8:
        score -= 15
    if length < 12 and classes < 2:
        score -= 10
    if _detect_sequences(password):
        score -= 10
    if _has_repeated_run(password):
        score -= 10
    if analysis["in_common_list"]:
        score -= 30

    return max(0, min(100, score))


def _rating(score: int) -> str:
    if score >= 85:
        return "Strong"
    if score >= 70:
        return "Good"
    if score >= 40:
        return "Fair"
    return "Weak"


def _recommendations(password: str, analysis: dict, score: int) -> list:
    """Build prioritized security recommendations."""
    recommendations = []
    rating = analysis["strength"]

    def add(text, priority):
        recommendations.append({"text": text, "priority": priority})

    if analysis["in_common_list"]:
        add("This password matches a known common/weak password list. Replace it immediately.", 1)

    if analysis["length"] < 8:
        add("Use at least 8 characters; 12+ is strongly recommended.", 2)
    elif analysis["length"] < 12:
        add("Increase length to 12 or more characters for stronger security.", 3)

    if analysis["classes_used"] < 2:
        add("Combine at least two character types (e.g., letters and numbers).", 3)
    if analysis["classes_used"] < 4 and analysis["length"] < 16:
        add("Add numbers and special characters to increase character variety.", 4)

    if not analysis["uppercase"]:
        add("Include at least one uppercase letter.", 5)
    if not analysis["lowercase"]:
        add("Include at least one lowercase letter.", 5)
    if not analysis["digits"]:
        add("Include at least one number.", 5)
    if not analysis["special"]:
        add("Include at least one special character (e.g., !@#$%).", 5)

    if _detect_sequences(password):
        add("Avoid predictable sequences such as '123', 'abc', or keyboard runs.", 4)
    if _has_repeated_run(password):
        add("Avoid repeated characters in a row.", 5)

    if rating == "Weak":
        add("Avoid dictionary words, names, and personal information.", 6)
    if rating == "Strong":
        add("Excellent password. Consider enabling multi-factor authentication as a second layer.", 8)
    elif score >= 70:
        add("Consider using a passphrase or password manager for unique credentials.", 7)

    return recommendations
