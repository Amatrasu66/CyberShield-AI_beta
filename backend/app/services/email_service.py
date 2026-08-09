"""
Phishing Email Detector Service.

DETERMINISTIC PLACEHOLDER (this phase):
Analysis is performed by transparent, deterministic heuristics so the API
contract can be exercised end-to-end without any ML model.

Future phase (ML integration): the heuristic analyzer will be replaced by the
trained model behind ``app/ml/phishing_detector.py``. The service method
signature ``analyze_email(content) -> dict`` will NOT change, so the API
contract remains stable.

Email content is never stored and never logged.
"""

import re

from ..errors import ValidationError

URL_REGEX = re.compile(r"(?:https?://|www\.)[^\s]+", re.IGNORECASE)

URGENT_WORDS = {
    "urgent", "immediately", "act now", "expires", "expire", "expiration",
    "suspended", "deactivated", "verify now", "account will be closed",
    "final notice", "limited time", "respond within", "asap",
}

CREDENTIAL_WORDS = {
    "password", "username", "login", "sign in", "bank", "account number",
    "ssn", "social security", "credit card", "debit card", "paypal",
    "verify your account", "update your information", "billing", "wire transfer",
}

GENERIC_GREETINGS = {"dear user", "dear customer", "dear member", "dear sir", "dear madam", "hi there", "hello user"}

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work"}

SPAM_ACTIONS = {"click here", "click the link", "download now", "free", "winner", "congratulations", "claim your prize"}


class EmailService:
    """Deterministic phishing analysis placeholder."""

    ANALYZER_ID = "deterministic-heuristic-placeholder"

    @staticmethod
    def analyze_email(content: str) -> dict:
        """Analyze email text and return phishing risk indicators."""
        if not isinstance(content, str):
            raise ValidationError("'content' must be a string", details={"field": "content"})

        text = content.lower()
        words = content.split()
        word_count = len(words)
        url_count = 0
        url_hosts = []
        suspicious_urls = 0
        for match in URL_REGEX.findall(content):
            url_count += 1
            host = match.replace("http://", "").replace("https://", "").replace("www.", "")
            host = host.split("/")[0].strip(".,;:!?")
            url_hosts.append(host)
            if host.endswith(tuple(SUSPICIOUS_TLDS)):
                suspicious_urls += 1

        indicators = []

        def add(name, severity, evidence):
            indicators.append({"name": name, "severity": severity, "evidence": evidence})

        if any(w in text for w in URGENT_WORDS):
            add("Urgency language", "High", "Contains urgent or pressure wording.")
        if any(w in text for w in CREDENTIAL_WORDS):
            add("Credential request", "High", "Requests sensitive/credential information.")
        if any(w in text for w in GENERIC_GREETINGS):
            add("Generic greeting", "Low", "Non-personalized greeting.")
        if any(w in text for w in SPAM_ACTIONS):
            add("Spam-style call to action", "Medium", "Contains promotional or urgent action phrases.")
        if url_count > 0:
            add("Embedded links", "Medium" if url_count >= 3 else "Low", f"{url_count} link(s) found.")
        if suspicious_urls:
            add("Suspicious link domains", "High", f"{suspicious_urls} link(s) use uncommon TLDs.")
        if "!!" in content or content.count("!") >= 3:
            add("Excessive punctuation", "Low", "Multiple exclamation marks.")
        if word_count > 0 and _uppercase_ratio(content) > 0.4 and word_count > 15:
            add("Excessive capitalization", "Medium", "Large portion of text is uppercase.")

        risk_score = _risk_score(indicators)
        risk_level = _risk_level(risk_score)
        confidence = min(0.95, round(0.5 + risk_score / 200, 2))

        return {
            "is_phishing": risk_level == "phishing",
            "risk_level": risk_level,
            "risk_score": risk_score,
            "confidence": confidence,
            "analyzer": EmailService.ANALYZER_ID,
            "summary": _summary(risk_level, risk_score),
            "indicators": indicators,
            "stats": {"word_count": word_count, "link_count": url_count},
        }


def _uppercase_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c.isupper()) / len(letters)


def _risk_score(indicators: list) -> int:
    weights = {"High": 30, "Medium": 20, "Low": 10}
    base = 10  # modest baseline
    score = base + sum(weights[i["severity"]] for i in indicators)
    return max(0, min(100, score))


def _risk_level(score: int) -> str:
    if score >= 70:
        return "phishing"
    if score >= 40:
        return "suspicious"
    return "safe"


def _summary(level: str, score: int) -> str:
    if level == "phishing":
        return f"High risk ({score}/100): multiple phishing indicators detected."
    if level == "suspicious":
        return f"Elevated risk ({score}/100): some indicators warrant review."
    return f"Low risk ({score}/100): no significant phishing indicators."
