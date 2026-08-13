"""
Website Security Scanner Service (Educational, non-destructive).

Performs a passive, non-intrusive analysis of a public website:

- HTTPS enforcement and TLS certificate validation
- Recommended security headers
- Cookie security attributes (Secure / HttpOnly / SameSite)
- CORS posture
- Information disclosure (Server / X-Powered-By)

Safety constraints:
- Only http/https targets; URL format is validated before scanning.
- Targets resolving to private/loopback addresses are refused (SSRF guard).
- Requests use short timeouts and never download the response body.
- No exploitation, no credential testing, no auth bypass, no fuzzing.
"""

import datetime
import re
import time
from urllib.parse import urlsplit

import requests

from ..database import get_supabase_client
from ..errors import ServiceUnavailableError, ValidationError
from ..utils.validators import is_private_host

RECOMMENDED_HEADERS = {
    "content_security_policy": {
        "header": "Content-Security-Policy",
        "label": "Content-Security-Policy",
        "recommendation": "Set a Content-Security-Policy to limit resource loading.",
    },
    "strict_transport_security": {
        "header": "Strict-Transport-Security",
        "label": "Strict-Transport-Security",
        "recommendation": "Enable HSTS (max-age >= 1 year) to force HTTPS.",
    },
    "x_content_type_options": {
        "header": "X-Content-Type-Options",
        "label": "X-Content-Type-Options",
        "recommendation": "Send 'X-Content-Type-Options: nosniff'.",
    },
    "x_frame_options": {
        "header": "X-Frame-Options",
        "label": "X-Frame-Options",
        "recommendation": "Send 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.",
    },
    "referrer_policy": {
        "header": "Referrer-Policy",
        "label": "Referrer-Policy",
        "recommendation": "Set a strict Referrer-Policy (e.g. no-referrer).",
    },
    "permissions_policy": {
        "header": "Permissions-Policy",
        "label": "Permissions-Policy",
        "recommendation": "Restrict sensitive browser features with Permissions-Policy.",
    },
}

COOKIE_ATTRIBUTE_FLAGS = ("secure", "httponly", "samesite")

HTTP_STATUS_WARN_THRESHOLD = 399


class ScannerService:
    """Passive website security analysis. Suitable for authorized education."""

    @staticmethod
    def scan_website(url: str, config: dict = None, user_id: str = None) -> dict:
        """Scan a validated URL and return structured security findings.

        ``user_id`` is the authenticated user UUID (``auth.uid()``); it scopes
        the persisted scan record and is never taken from the client.
        """
        from flask import current_app

        cfg = config or current_app.config

        if not cfg.get("SCANNER_ALLOW_PRIVATE_ADDRESSES", False) and is_private_host(url):
            raise ValidationError(
                "Target resolves to a private or loopback address and is refused "
                "to prevent scanner abuse.",
                details={"field": "url"},
            )

        started = time.perf_counter()
        fetch = ScannerService._fetch(url, cfg)
        duration_ms = round((time.perf_counter() - started) * 1000, 2)

        if fetch.get("error"):
            return {
                "target": url,
                "reachable": False,
                "error": fetch["error"],
                "message": fetch["error_message"],
                "score": 0,
                "grade": "F",
                "checks": [],
                "scan_duration_ms": duration_ms,
                "summary": "Target could not be scanned: " + fetch["error_message"],
            }

        checks = ScannerService._build_checks(fetch)
        passed = sum(1 for c in checks if c["status"] == "passed")
        failed = sum(1 for c in checks if c["status"] == "failed")
        warnings = sum(1 for c in checks if c["status"] == "warning")
        denominator = passed + failed
        score = round((passed / denominator) * 100) if denominator else 0

        result = {
            "target": url,
            "reachable": True,
            "final_url": fetch["final_url"],
            "final_status_code": fetch["status_code"],
            "score": score,
            "grade": _grade(score),
            "checks": checks,
            "scan_duration_ms": duration_ms,
            "summary": (
                f"{passed} passed, {failed} failed, {warnings} warning(s) out of {len(checks)} checks."
            ),
        }
        ScannerService._persist_scan(user_id, url, result)
        return result

    # ------------------------------------------------------------ internals
    @staticmethod
    def _persist_scan(user_id: str, target_url: str, result: dict) -> None:
        """Persist a completed website scan to ``public.website_scans``.

        Persistence is skipped when there is no authenticated ``user_id`` (e.g.
        direct service use) or when Supabase is not configured. Only completed
        (reachable) scans are stored. ``user_id`` always comes from the verified
        JWT, never from the client.
        """
        if not user_id or not result.get("reachable"):
            return
        client = get_supabase_client()
        if client is None:
            return
        payload = {
            "user_id": user_id,
            "target_url": target_url,
            "status": "completed",
            "security_score": result["score"],
            "risk_level": _risk_level(result["score"]),
            "findings": result["checks"],
        }
        try:
            client.table("website_scans").insert(payload).execute()
        except Exception as exc:
            raise ServiceUnavailableError(
                "Website scan results could not be stored",
                details={"table": "website_scans", "error": type(exc).__name__},
            )

    @staticmethod
    def _fetch(url: str, cfg) -> dict:
        """Fetch response headers only (never the body). Returns a structured dict."""
        result = {
            "error": None,
            "error_message": None,
            "final_url": url,
            "final_scheme": urlsplit(url).scheme,
            "status_code": None,
            "headers": {},
            "raw_set_cookie": [],
            "cert": None,
        }
        try:
            session = requests.Session()
            session.max_redirects = int(cfg.get("SCANNER_MAX_REDIRECTS", 5))
            response = session.get(
                url,
                timeout=int(cfg.get("SCANNER_TIMEOUT", 10)),
                stream=True,
                allow_redirects=True,
                verify=True,
                headers={
                    "User-Agent": cfg.get(
                        "SCANNER_USER_AGENT",
                        "CyberShieldAI-Scanner/1.0 (educational assessment)",
                    ),
                    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                },
            )
        except requests.exceptions.SSLError:
            result["error"] = "ssl"
            result["error_message"] = "TLS certificate could not be validated."
            return result
        except requests.exceptions.ConnectTimeout:
            result["error"] = "timeout"
            result["error_message"] = "Connection timed out."
            return result
        except requests.exceptions.ReadTimeout:
            result["error"] = "timeout"
            result["error_message"] = "Server took too long to respond."
            return result
        except requests.exceptions.TooManyRedirects:
            result["error"] = "redirects"
            result["error_message"] = "Too many redirects while following the URL."
            return result
        except requests.exceptions.ConnectionError:
            result["error"] = "connection"
            result["error_message"] = "Could not connect to the target server."
            return result
        except requests.exceptions.RequestException as exc:
            result["error"] = "request"
            result["error_message"] = "Request failed: " + type(exc).__name__
            return result

        with response:
            try:
                result["status_code"] = response.status_code
                result["final_url"] = response.url
                result["final_scheme"] = urlsplit(response.url).scheme
                result["headers"] = {k.lower(): v for k, v in response.headers.items()}
                # Set-Cookie is multi-valued; read it from the raw urllib3 headers.
                try:
                    raw_headers = response.raw.headers
                    result["raw_set_cookie"] = raw_headers.get_all("Set-Cookie", []) if hasattr(
                        raw_headers, "get_all"
                    ) else []
                except Exception:
                    result["raw_set_cookie"] = []
                result["cert"] = getattr(response, "cert", None)

                # Response-size guard: never read the body; flag oversized bodies.
                content_length = response.headers.get("Content-Length")
                max_size = int(cfg.get("SCANNER_MAX_RESPONSE_SIZE", 512_000))
                if content_length and content_length.isdigit() and int(content_length) > max_size:
                    result["size_warning"] = (
                        f"Response body exceeds the {max_size} byte scan limit; body was not downloaded."
                    )
            except Exception:
                result["error"] = "parse"
                result["error_message"] = "Could not read the server response."

        return result

    @staticmethod
    def _build_checks(fetch: dict) -> list:
        checks = []
        headers = fetch["headers"]
        final_scheme = fetch["final_scheme"]

        # --- HTTPS enforcement ---
        if final_scheme == "https":
            checks.append(_check("HTTPS enforcement", "passed", "Site is served over HTTPS.", "Keep HTTPS as the default."))
        else:
            checks.append(_check(
                "HTTPS enforcement",
                "failed",
                "Site is served over plain HTTP.",
                "Redirect all HTTP traffic to HTTPS.",
            ))

        # --- TLS certificate ---
        if final_scheme == "https":
            if fetch["cert"]:
                days = _cert_days_left(fetch["cert"])
                detail = "TLS certificate validated by the system trust store."
                if days is not None:
                    detail += f" Expires in ~{days} day(s)."
                checks.append(_check("TLS certificate", "passed", detail, "Renew before expiry."))
            else:
                checks.append(_check(
                    "TLS certificate",
                    "passed",
                    "TLS handshake succeeded (certificate accepted).",
                    "Monitor certificate expiry.",
                ))
        else:
            checks.append(_check(
                "TLS certificate",
                "info",
                "Not applicable: site is not served over HTTPS.",
                "Enable HTTPS to obtain a certificate.",
            ))

        # --- Recommended security headers ---
        for key, spec in RECOMMENDED_HEADERS.items():
            header = spec["header"]
            present = header.lower() in headers
            if key == "strict_transport_security" and final_scheme != "https":
                checks.append(_check(
                    spec["label"],
                    "info",
                    "HSTS only applies over HTTPS; site is currently HTTP.",
                    spec["recommendation"],
                ))
            elif present:
                checks.append(_check(spec["label"], "passed", f"Header present: {headers[header.lower()][:120]}", spec["recommendation"]))
            else:
                checks.append(_check(spec["label"], "failed", "Header is missing.", spec["recommendation"]))

        # --- Cookies ---
        checks.append(ScannerService._cookie_check(fetch))

        # --- CORS ---
        acao = headers.get("access-control-allow-origin")
        if acao is None:
            checks.append(_check("CORS policy", "passed", "No Access-Control-Allow-Origin header; cross-origin reads are restricted.", "Keep CORS disabled unless needed."))
        elif acao.strip() == "*":
            checks.append(_check("CORS policy", "warning", "Access-Control-Allow-Origin is set to '*' (any origin).", "Restrict CORS to trusted origins; avoid wildcard with credentials."))
        else:
            checks.append(_check("CORS policy", "info", f"Access-Control-Allow-Origin: {acao[:120]}", "Confirm the listed origins are trusted."))

        # --- Information disclosure ---
        disclosure = []
        if headers.get("server"):
            disclosure.append(f"Server header discloses: {headers['server'][:120]}")
        if headers.get("x-powered-by"):
            disclosure.append(f"X-Powered-By header discloses: {headers['x-powered-by'][:120]}")
        if disclosure:
            checks.append(_check("Information disclosure", "warning", "; ".join(disclosure), "Remove or obscure Server / X-Powered-By headers."))
        else:
            checks.append(_check("Information disclosure", "passed", "No server technology disclosure headers found.", "Keep it that way."))

        # --- Unusual response status ---
        status = fetch.get("status_code")
        if status is not None and status > HTTP_STATUS_WARN_THRESHOLD:
            checks.append(_check("Response status", "warning", f"Server returned HTTP {status}.", "Confirm this is expected."))

        # --- Oversized body note ---
        if fetch.get("size_warning"):
            checks.append(_check("Response size", "warning", fetch["size_warning"], "None."))

        return checks

    @staticmethod
    def _cookie_check(fetch: dict) -> dict:
        parsed = [_parse_cookie(raw) for raw in fetch["raw_set_cookie"]]
        parsed = [c for c in parsed if c]
        if not parsed:
            return _check(
                "Cookie security",
                "info",
                "No cookies were set by the target.",
                "Ensure any future cookies set Secure + HttpOnly.",
            )
        issues = []
        for cookie in parsed:
            missing = [flag for flag in COOKIE_ATTRIBUTE_FLAGS if not cookie.get(flag)]
            if missing:
                issues.append(f"{cookie['name']} missing: {', '.join(missing)}")
        if issues:
            return _check(
                "Cookie security",
                "warning",
                "; ".join(issues),
                "Set Secure, HttpOnly, and SameSite on all cookies.",
            )
        return _check(
            "Cookie security",
            "passed",
            f"All {len(parsed)} cookie(s) set Secure + HttpOnly (+ SameSite).",
            "Keep these attributes on all cookies.",
        )


def _check(name: str, status: str, detail: str, recommendation: str) -> dict:
    return {
        "name": name,
        "status": status,
        "detail": detail,
        "recommendation": recommendation,
    }


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _risk_level(score: int) -> str:
    """Map a 0-100 security score to a risk level (low/medium/high/critical)."""
    if score >= 75:
        return "low"
    if score >= 60:
        return "medium"
    if score >= 40:
        return "high"
    return "critical"


def _cert_days_left(cert: dict):
    """Return days until certificate expiry from a requests ``response.cert`` dict."""
    not_after = cert.get("notAfter")
    if not not_after:
        return None
    try:
        expiry = datetime.datetime.strptime(not_after, "%Y%m%d%H%M%SZ").replace(tzinfo=datetime.timezone.utc)
        return (expiry - datetime.datetime.now(datetime.timezone.utc)).days
    except (ValueError, TypeError):
        return None


def _parse_cookie(raw: str) -> dict:
    """Parse a raw Set-Cookie header into name + security attributes."""
    if not raw:
        return None
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    if not name:
        return None
    attrs = {"name": name, "secure": False, "httponly": False, "samesite": False}
    for part in parts[1:]:
        lowered = part.lower()
        if lowered == "secure":
            attrs["secure"] = True
        elif lowered == "httponly":
            attrs["httponly"] = True
        elif lowered.startswith("samesite"):
            value = part.split("=", 1)[1] if "=" in part else "true"
            attrs["samesite"] = value.strip() or True
    return attrs
