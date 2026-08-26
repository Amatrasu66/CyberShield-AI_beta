"""
Project Honey Pot Provider — HTTP:BL DNS-based lookup.

Security:
- Server-side access key only, never exposed to frontend
- Fixed hard-coded DNSBL endpoint (dnsbl.httpbl.org), not user-controlled
- No shell commands, no scraping, DNS only via socket
- Bounded timeout via ThreadPoolExecutor
- Strict IPv4 public validation, IPv6 rejected as unavailable
- Response validation: 127.V.T.S exact, numeric, first octet 127

HTTP:BL spec (docs.projecthoneypot.org):
  Query: <access_key>.<reversed_ipv4>.dnsbl.httpbl.org
  Positive: 127.<days>.<threat>.<visitor_type>
    days 0-255, threat 0-255, visitor_type 0-7 bitset
      0 search engine, 1 suspicious, 2 harvester, 4 comment spammer
  NXDOMAIN: no evidence -> UNKNOWN (not CLEAN)
  Any DNS error/timeout/malformed -> UNAVAILABLE
"""

from __future__ import annotations

import ipaddress
import socket
import concurrent.futures
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field, asdict
from typing import Optional

from ..config import get_config
from ..errors import ValidationError


# Hard-coded endpoint — never user-controlled
_HONEY_POT_DNSBL_DOMAIN = "dnsbl.httpbl.org"

# Visitor type bit definitions
_VISITOR_TYPE_NAMES = {
    0: "search_engine",
    1: "suspicious",
    2: "harvester",
    4: "comment_spammer",
}

_VISITOR_TYPE_LABELS = {
    0: "Search Engine",
    1: "Suspicious",
    2: "Harvester",
    3: "Suspicious + Harvester",
    4: "Comment Spammer",
    5: "Suspicious + Comment Spammer",
    6: "Harvester + Comment Spammer",
    7: "Suspicious + Harvester + Comment Spammer",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def visitor_type_name(code: int) -> str:
    return _VISITOR_TYPE_LABELS.get(code, f"unknown({code})")


def visitor_type_flags(code: int) -> list[str]:
    """Decode visitor_type bitset into normalized tags."""
    if code == 0:
        return ["search_engine"]
    flags: list[str] = []
    if code & 1:
        flags.append("suspicious")
    if code & 2:
        flags.append("harvester")
    if code & 4:
        flags.append("comment_spammer")
    return flags


def _confidence_from_threat(threat: int) -> str:
    if threat <= 0:
        return "none"
    if threat < 25:
        return "low"
    if threat < 50:
        return "medium"
    if threat < 75:
        return "high"
    return "very_high"


def _reputation_from_honeypot(visitor_type: int, threat: int) -> tuple[str, bool, bool]:
    """
    Normalize HoneyPot evidence to reputation.
    Rules per PHASE 2D-10:
    - V=0 (search_engine) -> UNKNOWN (not CLEAN) per 3B
    - T=0 -> unknown
    - T 1-39 suspicious, 40-74 suspicious, >=75 malicious (but keep suspicious vs malicious distinction)
    - Search engine never malicious/suspicious
    """
    if visitor_type == 0:
        return "unknown", False, False
    if threat == 0:
        # Has visitor type but zero threat -> unknown (low confidence evidence)
        return "unknown", False, False
    if threat >= 75:
        return "malicious", True, True
    if threat >= 1:
        return "suspicious", False, True
    return "unknown", False, False


# ------------------------------------------------------------------ ProviderEvidence

@dataclass
class ProviderEvidence:
    """Normalized provider evidence — provider-agnostic envelope."""

    ip: str
    provider: str  # e.g. project_honeypot, abuseipdb
    status: str  # available | unknown | unavailable
    reputation: str  # clean | unknown | suspicious | malicious | unavailable
    confidence: str  # none | low | medium | high | very_high
    threat_score: Optional[int] = None
    visitor_type: Optional[int] = None
    visitor_type_name: Optional[str] = None
    days_since_activity: Optional[int] = None
    last_seen: Optional[str] = None
    reason: Optional[str] = None
    checked_at: Optional[str] = None
    raw: Optional[dict] = None

    # Back-compat fields for assessment (mapped from evidence)
    malicious: bool = False
    suspicious: bool = False
    categories: list[str] = field(default_factory=list)
    evidence: Optional[dict] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def _get_access_key() -> str:
    try:
        from flask import current_app
        v = current_app.config.get("PROJECT_HONEYPOT_ACCESS_KEY")
        if v is not None:
            return str(v).strip()
    except Exception:
        pass
    try:
        cfg = get_config()
        return str(getattr(cfg, "PROJECT_HONEYPOT_ACCESS_KEY", "") or "").strip()
    except Exception:
        return ""


def _get_timeout() -> int:
    try:
        from flask import current_app
        v = current_app.config.get("PROJECT_HONEYPOT_TIMEOUT")
        if v is not None:
            return max(1, int(v))
    except Exception:
        pass
    try:
        cfg = get_config()
        return max(1, int(getattr(cfg, "PROJECT_HONEYPOT_TIMEOUT", 3) or 3))
    except Exception:
        return 3


def _is_public_ipv4(ip_str: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False
    if parsed.version != 4:
        return False
    # Block private/reserved etc same as is_private_ip but for IPv4 only
    if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved or parsed.is_multicast or parsed.is_unspecified:
        return False
    return True


class ProjectHoneyPotProvider:
    """HTTP:BL DNS provider."""

    provider_name = "project_honeypot"

    def __init__(self, access_key: str = None, timeout: int = None, dns_domain: str = None):
        # dns_domain hard-coded; ignore user-supplied
        self.access_key = (access_key if access_key is not None else _get_access_key()).strip()
        self.timeout = int(timeout) if timeout is not None else _get_timeout()
        self.dns_domain = _HONEY_POT_DNSBL_DOMAIN

    def check_ip(self, ip: str) -> ProviderEvidence:
        from ..utils.validators import validate_ip_address, is_private_ip

        checked_at = _now_iso()

        # Strict IP validation
        try:
            normalized = validate_ip_address(ip)
        except ValidationError:
            return ProviderEvidence(
                ip=ip,
                provider=self.provider_name,
                status="unavailable",
                reputation="unavailable",
                confidence="none",
                reason="invalid_ip",
                checked_at=checked_at,
                raw={},
            )

        # IPv6 check — HTTP:BL is IPv4 only
        try:
            parsed = ipaddress.ip_address(normalized)
            if parsed.version == 6:
                return ProviderEvidence(
                    ip=normalized,
                    provider=self.provider_name,
                    status="unavailable",
                    reputation="unavailable",
                    confidence="none",
                    reason="ipv6_unsupported",
                    checked_at=checked_at,
                    raw={"ip_version": 6},
                    evidence={},
                )
        except ValueError:
            pass

        # Private/reserved rejected before DNS
        if is_private_ip(normalized):
            return ProviderEvidence(
                ip=normalized,
                provider=self.provider_name,
                status="unavailable",
                reputation="unavailable",
                confidence="none",
                reason="private_ip_blocked",
                checked_at=checked_at,
                raw={},
            )

        # Also ensure public IPv4 (covers non-private but still maybe invalid)
        if not _is_public_ipv4(normalized):
            # Could be reserved etc already caught; fallback
            return ProviderEvidence(
                ip=normalized,
                provider=self.provider_name,
                status="unavailable",
                reputation="unavailable",
                confidence="none",
                reason="private_ip_blocked",
                checked_at=checked_at,
                raw={},
            )

        if not self.access_key:
            return ProviderEvidence(
                ip=normalized,
                provider=self.provider_name,
                status="unavailable",
                reputation="unavailable",
                confidence="none",
                reason="missing_api_key",
                checked_at=checked_at,
                raw={},
            )

        # Construct DNS query internally: <key>.<reversed_ip>.dnsbl.httpbl.org
        octets = normalized.split(".")
        reversed_ip = ".".join(reversed(octets))
        query = f"{self.access_key}.{reversed_ip}.{self.dns_domain}"

        # Bounded DNS resolution — do not use user-controlled DNS server
        try:
            result_ip = self._dns_lookup(query)
        except socket.timeout:
            return ProviderEvidence(
                ip=normalized,
                provider=self.provider_name,
                status="unavailable",
                reputation="unavailable",
                confidence="none",
                reason="timeout",
                checked_at=checked_at,
                raw={"query": "redacted"},
            )
        except socket.gaierror as exc:
            # Check NXDOMAIN vs other error
            # Python socket.gaierror for NXDOMAIN is EAI_NONAME (-2)
            # Use errno or message inspection
            err_str = str(exc).lower()
            if "name or service not known" in err_str or "nxdomain" in err_str or "noname" in err_str or exc.errno == -2 or exc.errno == 11001:
                # NXDOMAIN -> unknown (no evidence, not clean)
                return ProviderEvidence(
                    ip=normalized,
                    provider=self.provider_name,
                    status="unknown",
                    reputation="unknown",
                    confidence="none",
                    threat_score=None,
                    visitor_type=None,
                    visitor_type_name=None,
                    days_since_activity=None,
                    last_seen=None,
                    reason="no_result",
                    checked_at=checked_at,
                    raw={"response": "nxdomain"},
                    malicious=False,
                    suspicious=False,
                    categories=[],
                    evidence={"days_since_activity": None, "threat_score": None, "visitor_type": None, "visitor_type_flags": []},
                )
            return ProviderEvidence(
                ip=normalized,
                provider=self.provider_name,
                status="unavailable",
                reputation="unavailable",
                confidence="none",
                reason="dns_error",
                checked_at=checked_at,
                raw={"error": "dns_error"},
            )
        except concurrent.futures.TimeoutError:
            return ProviderEvidence(
                ip=normalized,
                provider=self.provider_name,
                status="unavailable",
                reputation="unavailable",
                confidence="none",
                reason="timeout",
                checked_at=checked_at,
                raw={"error": "timeout"},
            )
        except Exception:
            return ProviderEvidence(
                ip=normalized,
                provider=self.provider_name,
                status="unavailable",
                reputation="unavailable",
                confidence="none",
                reason="dns_error",
                checked_at=checked_at,
                raw={"error": "dns_error"},
            )

        if result_ip is None:
            # Treated as NXDOMAIN already, but fallback
            return ProviderEvidence(
                ip=normalized,
                provider=self.provider_name,
                status="unknown",
                reputation="unknown",
                confidence="none",
                reason="no_result",
                checked_at=checked_at,
                raw={"response": "nxdomain"},
                malicious=False,
                suspicious=False,
                categories=[],
                evidence={"days_since_activity": None, "threat_score": None, "visitor_type": None, "visitor_type_flags": []},
            )

        # Validate response format 127.D.T.V
        parts = result_ip.strip().split(".")
        if len(parts) != 4:
            return ProviderEvidence(
                ip=normalized,
                provider=self.provider_name,
                status="unavailable",
                reputation="unavailable",
                confidence="none",
                reason="malformed_response",
                checked_at=checked_at,
                raw={"response": result_ip},
            )
        try:
            octets_int = [int(p) for p in parts]
        except ValueError:
            return ProviderEvidence(
                ip=normalized,
                provider=self.provider_name,
                status="unavailable",
                reputation="unavailable",
                confidence="none",
                reason="malformed_response",
                checked_at=checked_at,
                raw={"response": result_ip},
            )
        if octets_int[0] != 127:
            return ProviderEvidence(
                ip=normalized,
                provider=self.provider_name,
                status="unavailable",
                reputation="unavailable",
                confidence="none",
                reason="malformed_response",
                checked_at=checked_at,
                raw={"response": result_ip},
            )
        days, threat, visitor_type = octets_int[1], octets_int[2], octets_int[3]
        # Validate ranges
        if not (0 <= days <= 255 and 0 <= threat <= 255 and 0 <= visitor_type <= 255):
            return ProviderEvidence(
                ip=normalized,
                provider=self.provider_name,
                status="unavailable",
                reputation="unavailable",
                confidence="none",
                reason="malformed_response",
                checked_at=checked_at,
                raw={"response": result_ip},
            )
        # Visitor type must be 0-7 per spec; above 7 is malformed
        if visitor_type > 7:
            return ProviderEvidence(
                ip=normalized,
                provider=self.provider_name,
                status="unavailable",
                reputation="unavailable",
                confidence="none",
                reason="malformed_response",
                checked_at=checked_at,
                raw={"response": result_ip},
            )

        # Days >? Valid 0-255.
        reputation, malicious, suspicious = _reputation_from_honeypot(visitor_type, threat)
        confidence = _confidence_from_threat(threat) if reputation not in ("unknown", "unavailable") else "none"
        # For unknown via V=0 or T=0, confidence none
        if reputation == "unknown":
            confidence = "none"

        flags = visitor_type_flags(visitor_type)
        vt_name = visitor_type_name(visitor_type)

        # last_seen = checked_at - days
        try:
            checked_dt = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
            last_seen_dt = checked_dt - timedelta(days=days)
            last_seen = last_seen_dt.isoformat()
        except Exception:
            last_seen = None

        status = "available" if reputation in ("suspicious", "malicious") else "unknown"
        # For unknown status due to V=0, keep unknown
        if reputation == "unknown":
            status = "unknown"

        raw_allowlist = {"response": result_ip, "days": days, "threat": threat, "visitor_type": visitor_type}

        evidence_payload = {
            "days_since_activity": days,
            "threat_score": threat,
            "visitor_type": visitor_type,
            "visitor_type_flags": flags,
            "visitor_type_name": vt_name,
        }

        return ProviderEvidence(
            ip=normalized,
            provider=self.provider_name,
            status=status,
            reputation=reputation,
            confidence=confidence,
            threat_score=threat,
            visitor_type=visitor_type,
            visitor_type_name=vt_name,
            days_since_activity=days,
            last_seen=last_seen,
            reason=None if reputation != "unavailable" else "malformed_response",
            checked_at=checked_at,
            raw=raw_allowlist,
            malicious=malicious,
            suspicious=suspicious,
            categories=flags,
            evidence=evidence_payload,
        )

    def _dns_lookup(self, query: str) -> Optional[str]:
        """Bounded DNS A lookup for HTTP:BL. Returns IP string or None for NXDOMAIN, raises on error."""
        timeout = self.timeout

        def _resolve():
            # Use gethostbyname for A record; http:BL returns 127.x.x.x
            return socket.gethostbyname(query)

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(_resolve)
        try:
            try:
                return future.result(timeout=timeout)
            except socket.gaierror:
                # Re-raise to handle NXDOMAIN vs error
                raise
            except concurrent.futures.TimeoutError:
                raise socket.timeout(f"DNS timeout after {timeout}s")
        finally:
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                executor.shutdown(wait=False)
