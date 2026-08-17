"""
Password Strength Analyzer Service.

Computes deterministic, non-ML security characteristics for a submitted
password: length, character classes, entropy estimate, strength classification,
crack-time estimate, and actionable recommendations.

Security guarantees:
- The plaintext password is never stored or logged.
- Only aggregate, derived characteristics are persisted.
- Only schema-defined metrics are written to ``public.password_scans``.
"""

import math
import re
import secrets
import string

from ..database import get_user_supabase_client
from ..errors import ServiceUnavailableError
from ..middleware.auth_middleware import get_current_access_token

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
    "1234", "1235", "111111", "iloveyou", "sunshine", "princess",
    "football", "baseball", "superman", "trustno1", "123123",
}

SEQUENCE_PATTERNS = [
    re.compile(r"(?:012|123|234|345|456|567|678|789|890|098|987|876|765|654|543|432|321|210)"),
    re.compile(r"(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)"),
    re.compile(r"(?:zyx|yxw|xwv|wvu|vut|uts|tsr|srq|rqp|qpo|pon|onm|nml|mlk|kjh|jih|ihg|hgf|gfe|fed|edc|dcb|cba)"),
    re.compile(r"qwerty|asdfgh|zxcvbn|qwertyuiop|asdf|zxcv"),
]

REPEATED_RUN_REGEX = re.compile(r"(.)\1{2,}")

# Keyboard layout patterns for detecting common keyboard walks
KEYBOARD_PATTERNS = [
    re.compile(r"qwerty|asdfgh|zxcvbn|qwertyuiop|asdf|zxcv"),
    re.compile(r"poiuy|lkjhg|mnbvc"),
    re.compile(r"1234567890|0987654321"),
]

# Common personal info patterns
YEAR_PATTERN = re.compile(r"(19|20)\d{2}")
DATE_PATTERN = re.compile(r"\d{1,2}[-/]\d{1,2}[-/]\d{2,4}")
PHONE_PATTERN = re.compile(r"(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")


class PasswordService:
    """Deterministic password strength analysis (no ML, no storage)."""

    @staticmethod
    def analyze_password(password: str, user_id: str = None) -> dict:
        """Analyze a password and return its security characteristics.

        ``password`` is used only for computation and discarded afterwards.
        ``user_id`` is the authenticated user UUID (``auth.uid()``); it is
        reserved for result scoping once persistence lands and is never taken
        from the client.
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
            "weaknesses": [],
            "score_breakdown": [],
            "security_checklist": [],
        }

        score = _strength_score(password, analysis)
        analysis["strength_score"] = score
        analysis["strength"] = _rating(score)
        analysis["weaknesses"] = _detect_weaknesses(password, analysis)
        analysis["score_breakdown"] = _score_breakdown(password, analysis, score)
        analysis["security_checklist"] = _security_checklist(password, analysis)
        analysis["recommendations"] = _recommendations(password, analysis, score)

        # Order recommendations from most to least impactful.
        analysis["recommendations"] = sorted(
            analysis["recommendations"], key=lambda r: r.get("priority", 99)
        )
        PasswordService._persist_scan(user_id, analysis)
        return analysis

    @staticmethod
    def _persist_scan(user_id: str, result: dict) -> None:
        """Persist a completed password analysis to ``public.password_scans``.

        Persistence is skipped when there is no authenticated ``user_id`` or when
        Supabase is not configured. Only schema-approved derived metrics are
        stored. The plaintext password and any password hash are never persisted.
        ``user_id`` always comes from the verified JWT, never from the client.
        The row is written through a user-scoped client authenticated with the
        request's access token, so RLS scopes it to ``auth.uid()``.
        """
        if not user_id:
            return
        client = get_user_supabase_client(get_current_access_token())
        if client is None:
            return

        payload = {
            "user_id": user_id,
            "password_length": result["length"],
            "entropy": result["entropy_bits"],
            "strength_score": result["strength_score"],
            "strength_label": result["strength"],
            "has_upper": result["uppercase"],
            "has_lower": result["lowercase"],
            "has_number": result["digits"],
            "has_symbol": result["special"],
            "breached": result["in_common_list"],
        }
        try:
            client.table("password_scans").insert(payload).execute()
        except Exception as exc:
            raise ServiceUnavailableError(
                "Password scan results could not be stored",
                details={"table": "password_scans", "error": type(exc).__name__},
            )


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


def _detect_weaknesses(password: str, analysis: dict) -> list:
    """Detect specific weakness patterns in the password."""
    weaknesses = []
    lowered = password.lower()
    length = analysis["length"]

    # Too short
    if length < 8:
        weaknesses.append({
            "code": "TOO_SHORT",
            "severity": "high",
            "title": "Password too short",
            "message": f"Password is only {length} characters long.",
            "recommendation": "Use at least 12 characters; longer is stronger."
        })
    elif length < 12:
        weaknesses.append({
            "code": "SHORT",
            "severity": "medium",
            "title": "Password could be longer",
            "message": f"Password is {length} characters; 12+ is recommended.",
            "recommendation": "Increase length to 12 or more characters."
        })

    # Common password
    if analysis["in_common_list"]:
        weaknesses.append({
            "code": "COMMON_PASSWORD",
            "severity": "critical",
            "title": "Common password detected",
            "message": "This password appears in known weak/common password lists.",
            "recommendation": "Choose a unique password not found in breach databases."
        })

    # Dictionary-like word detection (simple heuristic: common words > 4 chars)
    if _has_dictionary_word(lowered):
        weaknesses.append({
            "code": "DICTIONARY_WORD",
            "severity": "medium",
            "title": "Dictionary-like word detected",
            "message": "The password contains a common dictionary word.",
            "recommendation": "Avoid common words; use a passphrase of random words instead."
        })

    # Repeated characters (aaa, 111, etc.)
    if _has_repeated_run(password):
        weaknesses.append({
            "code": "REPEATED_CHARACTERS",
            "severity": "medium",
            "title": "Repeated characters",
            "message": "The password contains 3 or more identical characters in a row.",
            "recommendation": "Avoid runs of the same character (e.g., 'aaa', '111')."
        })

    # Repeated substrings (e.g., "abcabc", "123123")
    repeated_substring = _detect_repeated_substring(password)
    if repeated_substring:
        weaknesses.append({
            "code": "REPEATED_SUBSTRING",
            "severity": "medium",
            "title": "Repeated substring pattern",
            "message": f"The password contains a repeated substring: '{repeated_substring}'.",
            "recommendation": "Avoid repeating sequences of characters."
        })

    # Sequential characters (123, abc, etc.)
    if _detect_sequences(password):
        weaknesses.append({
            "code": "SEQUENTIAL_PATTERN",
            "severity": "medium",
            "title": "Sequential pattern detected",
            "message": "The password contains sequential characters (e.g., '123', 'abc').",
            "recommendation": "Avoid predictable sequences like '123', 'abc', or keyboard runs."
        })

    # Keyboard patterns
    if _detect_keyboard_pattern(lowered):
        weaknesses.append({
            "code": "KEYBOARD_PATTERN",
            "severity": "medium",
            "title": "Keyboard pattern detected",
            "message": "The password contains a common keyboard walk pattern.",
            "recommendation": "Avoid keyboard patterns like 'qwerty', 'asdfgh', or 'zxcvbn'."
        })

    # Predictable year suffix (e.g., 2024, 2023)
    year_match = YEAR_PATTERN.search(password)
    if year_match:
        year = int(year_match.group())
        if 1900 <= year <= 2030:
            weaknesses.append({
                "code": "PREDICTABLE_YEAR",
                "severity": "medium",
                "title": "Predictable year suffix",
                "message": f"The password contains a year-like number ({year}).",
                "recommendation": "Avoid using years, birth years, or current years in passwords."
            })

    # Date-like patterns
    if DATE_PATTERN.search(password):
        weaknesses.append({
            "code": "DATE_PATTERN",
            "severity": "medium",
            "title": "Date-like pattern",
            "message": "The password contains a date-like sequence.",
            "recommendation": "Avoid using dates (birthdays, anniversaries) in passwords."
        })

    # Phone number-like patterns
    if PHONE_PATTERN.search(password):
        weaknesses.append({
            "code": "PHONE_PATTERN",
            "severity": "low",
            "title": "Phone number pattern",
            "message": "The password contains a sequence resembling a phone number.",
            "recommendation": "Avoid using phone numbers in passwords."
        })

    # Simple substitutions (leetspeak)
    if _has_simple_substitution(lowered):
        weaknesses.append({
            "code": "SIMPLE_SUBSTITUTION",
            "severity": "low",
            "title": "Simple character substitution",
            "message": "The password uses predictable substitutions (e.g., 'a'->'@', 'e'->'3').",
            "recommendation": "Simple substitutions like '@' for 'a' add little security."
        })

    # Excessive predictability (low entropy relative to length)
    if analysis["entropy_bits"] < length * 2.5 and length >= 8:
        weaknesses.append({
            "code": "EXCESSIVE_PREDICTABILITY",
            "severity": "medium",
            "title": "Low entropy for length",
            "message": "The password has lower entropy than expected for its length.",
            "recommendation": "Increase randomness; avoid patterns and dictionary words."
        })

    return weaknesses


def _has_dictionary_word(password: str) -> bool:
    """Simple check for common dictionary words (length >= 5)."""
    common_words = {
        "password", "welcome", "admin", "login", "access", "secure", "secret",
        "monkey", "dragon", "sunshine", "princess", "football", "baseball",
        "superman", "batman", "starwars", "master", "shadow", "hunter",
        "michael", "jennifer", "jessica", "ashley", "amanda", "sarah",
        "david", "john", "james", "robert", "william", "joseph",
        "computer", "internet", "network", "system", "server", "client",
        "database", "software", "hardware", "keyboard", "monitor", "printer"
    }
    for word in common_words:
        if len(word) >= 5 and word in password:
            return True
    return False


def _detect_repeated_substring(password: str) -> str | None:
    """Detect repeated substrings of length >= 3."""
    length = len(password)
    for sub_len in range(3, length // 2 + 1):
        for i in range(length - 2 * sub_len + 1):
            substr = password[i:i + sub_len]
            if password.count(substr) >= 2:
                return substr
    return None


def _detect_keyboard_pattern(password: str) -> bool:
    """Detect common keyboard walk patterns."""
    return any(pattern.search(password) for pattern in KEYBOARD_PATTERNS)


def _has_simple_substitution(password: str) -> bool:
    """Detect simple leetspeak substitutions."""
    substitutions = [
        ('a', '@'), ('a', '4'),
        ('e', '3'),
        ('i', '1'), ('i', '!'),
        ('o', '0'),
        ('s', '$'), ('s', '5'),
        ('t', '7'), ('t', '+'),
        ('l', '1'),
        ('g', '9'),
        ('b', '8'),
    ]
    # Check if password has leetspeak but would be a common word without it
    normalized = password
    for char, sub in substitutions:
        normalized = normalized.replace(sub, char)
    return _has_dictionary_word(normalized) and normalized != password


def _score_breakdown(password: str, analysis: dict, score: int) -> list:
    """Generate transparent score breakdown based on scoring factors."""
    length = analysis["length"]
    classes = analysis["classes_used"]
    bits = analysis["entropy_bits"]
    in_common = analysis["in_common_list"]

    breakdown = []

    # Length factor (0-30 points in original scoring)
    length_score = min(30, int(length * 1.5))
    breakdown.append({
        "factor": "Length",
        "score": min(100, int(length_score / 30 * 100)),
        "status": "good" if length >= 12 else ("warning" if length >= 8 else "danger"),
        "details": f"{length} characters"
    })

    # Character variety factor (0-30 points)
    variety_score = min(30, max(0, classes - 1) * 10)
    breakdown.append({
        "factor": "Character Variety",
        "score": min(100, int(variety_score / 30 * 100)) if classes > 1 else 0,
        "status": "good" if classes >= 3 else ("warning" if classes >= 2 else "danger"),
        "details": f"{classes}/4 character classes"
    })

    # Entropy factor (0-25 points)
    if bits >= 80:
        entropy_score = 25
        entropy_status = "good"
    elif bits >= 60:
        entropy_score = 20
        entropy_status = "good"
    elif bits >= 40:
        entropy_score = 15
        entropy_status = "warning"
    elif bits >= 28:
        entropy_score = 10
        entropy_status = "warning"
    else:
        entropy_score = 0
        entropy_status = "danger"
    breakdown.append({
        "factor": "Entropy",
        "score": min(100, int(entropy_score / 25 * 100)),
        "status": entropy_status,
        "details": f"{bits:.1f} bits"
    })

    # Common password exposure (penalty up to -30)
    exposure_score = 0 if in_common else 100
    breakdown.append({
        "factor": "Common Password Exposure",
        "score": exposure_score,
        "status": "danger" if in_common else "good",
        "details": "Found in common lists" if in_common else "Not in common lists"
    })

    # Pattern penalties
    pattern_penalty = 0
    if _detect_sequences(password):
        pattern_penalty += 10
    if _has_repeated_run(password):
        pattern_penalty += 10
    pattern_score = max(0, 100 - pattern_penalty)
    breakdown.append({
        "factor": "Predictable Patterns",
        "score": pattern_score,
        "status": "good" if pattern_penalty == 0 else ("warning" if pattern_penalty <= 10 else "danger"),
        "details": "No predictable patterns" if pattern_penalty == 0 else f"{pattern_penalty} points in penalties"
    })

    return breakdown


def _security_checklist(password: str, analysis: dict) -> list:
    """Generate a structured security checklist.

    Objectively analyzable conditions carry ``status`` ``"passed"`` or
    ``"failed"`` with a boolean ``passed`` value. Advisory guidance that cannot
    be verified from the password alone (password reuse, password-manager
    usage, MFA configuration) carries ``status`` ``"advisory"`` with ``passed``
    ``None``, so clients never mistake a recommendation for a verified check.
    """
    length = analysis["length"]
    in_common = analysis["in_common_list"]
    weaknesses = _detect_weaknesses(password, analysis)

    checklist = []

    # Sufficient length
    checklist.append({
        "item": "Sufficient length (12+ characters)",
        "status": "passed" if length >= 12 else "failed",
        "passed": length >= 12,
        "details": f"Current length: {length} characters"
    })

    # Not commonly used
    checklist.append({
        "item": "Not a commonly used password",
        "status": "passed" if not in_common else "failed",
        "passed": not in_common,
        "details": "Found in common password lists" if in_common else "Not found in common lists"
    })

    # No obvious predictable patterns
    has_patterns = any(w["code"] in ("SEQUENTIAL_PATTERN", "KEYBOARD_PATTERN", "REPEATED_CHARACTERS", "REPEATED_SUBSTRING") for w in weaknesses)
    checklist.append({
        "item": "No obvious predictable patterns",
        "status": "passed" if not has_patterns else "failed",
        "passed": not has_patterns,
        "details": "Predictable patterns detected" if has_patterns else "No predictable patterns found"
    })

    # No obvious personal-information pattern
    has_personal = any(w["code"] in ("PREDICTABLE_YEAR", "DATE_PATTERN", "PHONE_PATTERN") for w in weaknesses)
    checklist.append({
        "item": "No obvious personal-information pattern",
        "status": "passed" if not has_personal else "failed",
        "passed": not has_personal,
        "details": "Possible personal-information pattern detected" if has_personal else "No personal-information patterns detected"
    })

    # Advisory items. These are recommendations the tool cannot verify from the
    # password alone, so they must never be reported as a passed check.
    checklist.append({
        "item": "Use a unique password for each account",
        "status": "advisory",
        "passed": None,
        "details": "Recommendation — this tool cannot determine whether this password is reused elsewhere. Always use a unique password for each account."
    })

    checklist.append({
        "item": "Consider using a password manager",
        "status": "advisory",
        "passed": None,
        "details": "Recommendation — this tool cannot verify how you store credentials. A password manager helps generate and store unique, strong passwords."
    })

    checklist.append({
        "item": "Enable multi-factor authentication (MFA)",
        "status": "advisory",
        "passed": None,
        "details": "Recommendation — this tool cannot inspect your account's MFA configuration. MFA adds a critical second layer of security beyond the password."
    })

    return checklist


# ============================================================
# Password Generation (Phase 2)
# ============================================================

# Curated wordlist for passphrase generation (EFF-style, ~7776 words would be ideal,
# but we use a smaller curated set for practicality). Words are 3-8 chars, common,
# distinct, and easy to spell.
PASSPHRASE_WORDLIST = [
    "cactus", "orbit", "lantern", "velvet", "river", "anchor", "bamboo", "crystal",
    "diamond", "eagle", "falcon", "galaxy", "harbor", "island", "jungle", "kayak",
    "lobster", "marble", "nebula", "ocean", "pebble", "quasar", "rainbow", "sapphire",
    "tundra", "unicorn", "volcano", "willow", "xenon", "zephyr", "alpine", "breeze",
    "canyon", "delta", "ember", "frost", "glacier", "horizon", "infinity", "jasmine",
    "kelp", "lagoon", "meadow", "northern", "opal", "prairie", "quartz", "ridge",
    "summit", "tidal", "upland", "valley", "waterfall", "yarrow", "zenith", "amber",
    "blossom", "coral", "driftwood", "evergreen", "fern", "geyser", "heather", "ivory",
    "jade", "kelp", "lotus", "magnolia", "nightfall", "orchid", "pinecone", "quill",
    "rosewood", "sequoia", "thistle", "undertow", "vine", "wildflower", "yucca", "zephyr",
    "acorn", "bluebird", "crimson", "dewdrop", "firefly", "goldenrod", "hummingbird",
    "indigo", "juniper", "kiwi", "larkspur", "moonlight", "nectar", "owlet", "petal",
    "quince", "redwood", "starlight", "tigerlily", "umbra", "violet", "whirlwind",
    "xylophone", "yesteryear", "zinnia", "apple", "blossom", "cherry", "daisy",
    "elderberry", "fig", "grape", "honeysuckle", "iris", "jasmine", "kiwi", "lavender",
    "marigold", "nutmeg", "olive", "peony", "quince", "rosemary", "sage", "thyme",
    "umbrella", "vanilla", "wisteria", "xylopia", "yam", "zucchini", "acorn", "birch",
    "cedar", "dogwood", "elm", "fir", "ginkgo", "hickory", "ironwood", "juniper",
    "kapok", "laurel", "maple", "oak", "palm", "quercus", "redwood", "spruce",
    "tamarack", "upas", "vine", "walnut", "xanthium", "yew", "zelkova", "anchor",
    "beacon", "compass", "drift", "equator", "flint", "granite", "harbor", "iceberg",
    "jetstream", "knot", "latitude", "meridian", "navigate", "oasis", "peak", "quay",
    "reef", "shore", "tide", "undertow", "voyage", "wave", "xebec", "yardarm", "zenith"
]

# Character set for random password generation (avoiding ambiguous chars: l, 1, I, O, 0)
RANDOM_PASSWORD_CHARS = (
    "abcdefghijkmnopqrstuvwxyz"  # lowercase without l
    "ABCDEFGHJKLMNPQRSTUVWXYZ"   # uppercase without I, O
    "23456789"                    # digits without 0, 1
    "!@#$%^&*_-+=?"               # special chars
)


class PasswordGenerator:
    """Cryptographically secure password generation."""

    @staticmethod
    def generate_passphrase(words: int = 5, delimiter: str = "-") -> dict:
        """
        Generate a secure passphrase using cryptographically random word selection.

        Args:
            words: Number of words (4-6)
            delimiter: Separator between words

        Returns:
            Dict with generated passphrase and metadata
        """
        if not 4 <= words <= 6:
            raise ValueError("words must be between 4 and 6")

        # Use secrets.SystemRandom for cryptographically secure selection
        rng = secrets.SystemRandom()
        selected_words = [rng.choice(PASSPHRASE_WORDLIST) for _ in range(words)]

        passphrase = delimiter.join(selected_words)

        return {
            "password": passphrase,
            "type": "passphrase",
            "words": words,
            "delimiter": delimiter,
            "length": len(passphrase),
        }

    @staticmethod
    def generate_random_password(length: int = 20) -> dict:
        """
        Generate a secure random password using cryptographically secure RNG.

        Args:
            length: Password length (8-64)

        Returns:
            Dict with generated password and metadata
        """
        if not 8 <= length <= 64:
            raise ValueError("length must be between 8 and 64")

        rng = secrets.SystemRandom()
        password = "".join(rng.choice(RANDOM_PASSWORD_CHARS) for _ in range(length))

        return {
            "password": password,
            "type": "random",
            "length": length,
            "charset_size": len(RANDOM_PASSWORD_CHARS),
        }
