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

from ..database import get_user_supabase_client
from ..errors import ServiceUnavailableError, ValidationError
from ..middleware.auth_middleware import get_current_access_token

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
    def analyze_email(content: str, user_id: str = None) -> dict:
        """Analyze email text and return phishing risk indicators.

        ``user_id`` is the authenticated user UUID (``auth.uid()``); it is
        reserved for result scoping once persistence lands and is never taken
        from the client.
        """
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

        result = {
            "is_phishing": risk_level == "phishing",
            "risk_level": risk_level,
            "risk_score": risk_score,
            "confidence": confidence,
            "analyzer": EmailService.ANALYZER_ID,
            "summary": _summary(risk_level, risk_score),
            "indicators": indicators,
            "stats": {"word_count": word_count, "link_count": url_count},
        }
        EmailService._persist_scan(user_id, content, result)
        return result

    @staticmethod
    def _persist_scan(user_id: str, email_content: str, result: dict) -> None:
        """Persist a completed email scan to ``public.email_scans``.

        Persistence is skipped when there is no authenticated ``user_id`` or when
        Supabase is not configured. Only schema-approved fields are stored.
        Raw email content is never persisted; only indicators/findings and
        metadata are stored. ``user_id`` always comes from the verified JWT,
        never from the client. The row is written through a user-scoped client
        authenticated with the request's access token, so RLS scopes it to
        ``auth.uid()``.
        """
        if not user_id:
            return
        client = get_user_supabase_client(get_current_access_token())
        if client is None:
            return

        subject = EmailService._extract_subject(email_content)
        sender_email = EmailService._extract_sender(email_content)
        predicted_label = "phishing" if result["is_phishing"] else "safe"

        payload = {
            "user_id": user_id,
            "subject": subject,
            "sender_email": sender_email,
            "predicted_label": predicted_label,
            "confidence": result["confidence"],
            "risk_level": _stored_risk_level(result["risk_level"]),
            "indicators": result["indicators"],
            "model_version": EmailService.ANALYZER_ID,
        }
        try:
            client.table("email_scans").insert(payload).execute()
        except Exception as exc:
            raise ServiceUnavailableError(
                "Email scan results could not be stored",
                details={"table": "email_scans", "error": type(exc).__name__},
            )

    @staticmethod
    def _extract_subject(content: str) -> str | None:
        """Extract subject line from email content if present."""
        for line in content.splitlines():
            if line.lower().startswith("subject:"):
                return line.split(":", 1)[1].strip()
        return None

    @staticmethod
    def _extract_sender(content: str) -> str | None:
        """Extract sender email from email content if present."""
        import re
        for line in content.splitlines():
            if line.lower().startswith("from:"):
                match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", line)
                if match:
                    return match.group(0)
        return None


def _stored_risk_level(risk_level: str) -> str:
    """Map the classification-level risk to the DB severity vocabulary.

    ``public.email_scans.risk_level`` is constrained to
    ``('low', 'medium', 'high', 'critical')``. The classification
    (``phishing``/``suspicious``/``safe``) stays in the API response only.
    """
    return {
        "phishing": "critical",
        "suspicious": "medium",
        "safe": "low",
    }.get(risk_level, "low")


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
