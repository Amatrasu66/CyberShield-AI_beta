"""
IP Reputation / Threat Intelligence Service.

Provider-independent abstraction for IP reputation checks.

Architecture:
    IPReputationService (facade)
        ↓
    IPReputationProvider (protocol)
        ↓
    AbuseIPDBProvider (concrete) / NullProvider

Normalized result is always returned to callers; provider-specific
payloads never leak to the frontend.

Security:
- Strict IP validation via validate_ip_address
- Private/loopback/link-local/reserved/multicast blocked before external call
- Fixed provider URL, no user-controlled URL
- Bounded timeout and max response bytes
- API key from env, never exposed
- Private IPs never sent to provider
"""

from __future__ import annotations

import ipaddress
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional, Protocol

import requests

from ..config import get_config
from ..errors import ValidationError


# ------------------------------------------------------------------ normalized result

@dataclass
class ReputationResult:
    """Provider-independent reputation result."""
    ip: str
    reputation: str  # unknown | clean | suspicious | malicious | unavailable
    confidence: Optional[str] = None  # low | medium | high | very_high | none
    malicious: bool = False
    suspicious: bool = False
    reports: int = 0
    country: Optional[str] = None
    asn: Optional[int] = None
    organization: Optional[str] = None
    isp: Optional[str] = None
    last_reported_at: Optional[str] = None
    provider: str = "unknown"
    checked_at: Optional[str] = None
    # Optional extra for unavailable reason, not exposed as stack trace
    reason: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        # Remove None reason unless needed? keep but frontend can ignore
        return d


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _confidence_from_score(score: int) -> str:
    if score <= 0:
        return "none"
    if score < 25:
        return "low"
    if score < 50:
        return "medium"
    if score < 75:
        return "high"
    return "very_high"


def _reputation_from_abuse(score: int, reports: int, is_whitelisted: bool) -> tuple[str, bool, bool]:
    """Map AbuseIPDB fields to normalized reputation."""
    if is_whitelisted:
        return "clean", False, False
    if reports == 0 and score == 0:
        return "unknown", False, False
    if score >= 75:
        return "malicious", True, True
    if score >= 25 or reports >= 5:
        return "suspicious", False, True
    if score > 0:
        return "suspicious", False, True
    return "unknown", False, False


# ------------------------------------------------------------------ provider protocol

class IPReputationProvider(ABC):
    """Abstract provider — must not expose provider-specific structures."""

    provider_name: str = "unknown"

    @abstractmethod
    def check_ip(self, ip: str) -> ReputationResult:
        """Check reputation for a single validated public IP."""
        ...


# ------------------------------------------------------------------ AbuseIPDB provider

class AbuseIPDBProvider(IPReputationProvider):
    """AbuseIPDB implementation (https://api.abuseipdb.com/api/v2/check)."""

    provider_name = "abuseipdb"

    def __init__(self, api_key: str, timeout: int = 5, max_bytes: int = 32768, base_url: Optional[str] = None):
        self.api_key = (api_key or "").strip()
        self.timeout = int(timeout)
        self.max_bytes = int(max_bytes)
        cfg = get_config()
        self.base_url = (base_url or cfg.IP_REPUTATION_ABUSEIPDB_URL or "https://api.abuseipdb.com/api/v2/check").strip()

    def check_ip(self, ip: str) -> ReputationResult:
        # Precondition: ip already validated as public; but double-check
        from ..utils.validators import is_private_ip
        if is_private_ip(ip):
            # Should have been blocked earlier; return unavailable without leaking to provider
            return ReputationResult(
                ip=ip,
                reputation="unavailable",
                confidence="none",
                provider=self.provider_name,
                checked_at=_now_iso(),
                reason="private_ip_blocked",
            )
        if not self.api_key:
            return ReputationResult(
                ip=ip,
                reputation="unavailable",
                confidence="none",
                provider=self.provider_name,
                checked_at=_now_iso(),
                reason="missing_api_key",
            )

        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}

        try:
            resp = requests.get(
                self.base_url,
                headers=headers,
                params=params,
                timeout=self.timeout,
            )
        except requests.Timeout:
            return ReputationResult(ip=ip, reputation="unavailable", confidence="none", provider=self.provider_name, checked_at=_now_iso(), reason="timeout")
        except requests.RequestException:
            return ReputationResult(ip=ip, reputation="unavailable", confidence="none", provider=self.provider_name, checked_at=_now_iso(), reason="network_error")

        # Bounded size — truncate if too large
        content_length = resp.headers.get("Content-Length")
        if content_length and int(content_length) > self.max_bytes:
            return ReputationResult(ip=ip, reputation="unavailable", confidence="none", provider=self.provider_name, checked_at=_now_iso(), reason="response_too_large")

        # Handle non-2xx as unavailable with specific reason, not exception
        if resp.status_code == 429:
            return ReputationResult(ip=ip, reputation="unavailable", confidence="none", provider=self.provider_name, checked_at=_now_iso(), reason="rate_limited")
        if resp.status_code in (401, 403):
            return ReputationResult(ip=ip, reputation="unavailable", confidence="none", provider=self.provider_name, checked_at=_now_iso(), reason="auth_failed")
        if resp.status_code >= 500:
            return ReputationResult(ip=ip, reputation="unavailable", confidence="none", provider=self.provider_name, checked_at=_now_iso(), reason="provider_error")
        if resp.status_code != 200:
            return ReputationResult(ip=ip, reputation="unavailable", confidence="none", provider=self.provider_name, checked_at=_now_iso(), reason=f"http_{resp.status_code}")

        # Truncate body
        text = resp.text
        if len(text.encode("utf-8")) > self.max_bytes:
            return ReputationResult(ip=ip, reputation="unavailable", confidence="none", provider=self.provider_name, checked_at=_now_iso(), reason="response_too_large")

        try:
            payload = resp.json()
        except Exception:
            return ReputationResult(ip=ip, reputation="unavailable", confidence="none", provider=self.provider_name, checked_at=_now_iso(), reason="malformed_response")

        # AbuseIPDB shape: {"data": {"ipAddress": "...", "abuseConfidenceScore": 42, "totalReports": 5, ...}}
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            return ReputationResult(ip=ip, reputation="unavailable", confidence="none", provider=self.provider_name, checked_at=_now_iso(), reason="malformed_response")

        try:
            score = int(data.get("abuseConfidenceScore", 0) or 0)
            reports = int(data.get("totalReports", 0) or 0)
            is_whitelisted = bool(data.get("isWhitelisted", False))
            country = data.get("countryCode")
            # AbuseIPDB provides asn as numeric? Actually not direct; try data.get("asn") if present
            asn_raw = data.get("asn")
            asn_val: Optional[int] = None
            if asn_raw is not None:
                try:
                    asn_val = int(str(asn_raw).replace("AS", ""))
                except Exception:
                    asn_val = None
            isp = data.get("isp")
            org = data.get("organization") or data.get("usageType") or isp
            last_reported = data.get("lastReportedAt")
        except Exception:
            return ReputationResult(ip=ip, reputation="unavailable", confidence="none", provider=self.provider_name, checked_at=_now_iso(), reason="malformed_response")

        reputation, malicious, suspicious = _reputation_from_abuse(score, reports, is_whitelisted)
        confidence = _confidence_from_score(score)

        return ReputationResult(
            ip=ip,
            reputation=reputation,
            confidence=confidence,
            malicious=malicious,
            suspicious=suspicious,
            reports=reports,
            country=country,
            asn=asn_val,
            organization=org,
            isp=isp,
            last_reported_at=last_reported,
            provider=self.provider_name,
            checked_at=_now_iso(),
        )


class NullProvider(IPReputationProvider):
    """Fallback when disabled / unknown provider."""
    provider_name = "unavailable"

    def check_ip(self, ip: str) -> ReputationResult:
        return ReputationResult(ip=ip, reputation="unavailable", confidence="none", provider=self.provider_name, checked_at=_now_iso(), reason="provider_disabled")


# ------------------------------------------------------------------ service facade

class IPReputationService:
    """Facade managing provider selection, validation, resolution."""

    @staticmethod
    def _get_provider() -> IPReputationProvider:
        # Prefer Flask app config when available (request or app context)
        try:
            from flask import current_app
            enabled = current_app.config.get("IP_REPUTATION_ENABLED")
            if enabled is not None:
                if not enabled:
                    return NullProvider()
                provider_name = (current_app.config.get("IP_REPUTATION_PROVIDER", "abuseipdb") or "abuseipdb").strip().lower()
                if provider_name == "abuseipdb":
                    return AbuseIPDBProvider(
                        api_key=current_app.config.get("IP_REPUTATION_API_KEY", ""),
                        timeout=int(current_app.config.get("IP_REPUTATION_TIMEOUT", 5) or 5),
                        max_bytes=int(current_app.config.get("IP_REPUTATION_MAX_RESPONSE_BYTES", 32768) or 32768),
                        base_url=current_app.config.get("IP_REPUTATION_ABUSEIPDB_URL", "https://api.abuseipdb.com/api/v2/check"),
                    )
                return NullProvider()
        except RuntimeError:
            pass
        except Exception:
            pass
        cfg = get_config()
        if not cfg.IP_REPUTATION_ENABLED:
            return NullProvider()
        provider_name = (cfg.IP_REPUTATION_PROVIDER or "abuseipdb").strip().lower()
        if provider_name == "abuseipdb":
            return AbuseIPDBProvider(
                api_key=cfg.IP_REPUTATION_API_KEY,
                timeout=cfg.IP_REPUTATION_TIMEOUT,
                max_bytes=cfg.IP_REPUTATION_MAX_RESPONSE_BYTES,
                base_url=cfg.IP_REPUTATION_ABUSEIPDB_URL,
            )
        # Unknown provider -> unavailable
        return NullProvider()

    @staticmethod
    def check_ip(ip: str) -> ReputationResult:
        """Validate and check a single IP address.

        Cache flow (after validation, private block):
          - if caching disabled → provider direct
          - else lookup (ip, provider) → if fresh return cached
          - else call provider → if not unavailable, upsert cache
        Private IPs never reach provider or cache.
        """
        from ..utils.validators import validate_ip_address, is_private_ip
        # Strict validation
        normalized = validate_ip_address(ip)
        if is_private_ip(normalized):
            raise ValidationError(
                "Private or reserved IP addresses cannot be checked for reputation",
                details={"field": "ip"},
            )
        provider = IPReputationService._get_provider()
        # NullProvider means disabled/unknown → no cache
        if provider.provider_name == "unavailable":
            return provider.check_ip(normalized)
        # Attempt cache lookup (handles enabled check internally)
        try:
            from .ip_reputation_cache_service import IPReputationCacheService
            cached = IPReputationCacheService.get(normalized, provider.provider_name)
            if cached is not None:
                return cached
        except Exception:
            # Cache must never break provider flow
            pass
        result = provider.check_ip(normalized)
        try:
            from .ip_reputation_cache_service import IPReputationCacheService
            IPReputationCacheService.put(result)
        except Exception:
            pass
        return result

    @staticmethod
    def check_target(target: str) -> ReputationResult:
        """Resolve hostname to IP (if needed) then check reputation.

        Reuses existing safe resolution; blocks private before provider call.
        """
        from ..utils.validators import validate_hostname_or_ip, is_private_hostname

        # Resolve config and validate target — prefer Flask current_app if available
        try:
            from flask import current_app
            max_len = current_app.config.get("URL_MAX_LENGTH", 2048)
            enabled = current_app.config.get("IP_REPUTATION_ENABLED")
            if enabled is None:
                from ..config import get_config as _gc
                enabled = _gc().IP_REPUTATION_ENABLED
            if not enabled:
                normalized_target = validate_hostname_or_ip(target, max_length=max_len)
                return ReputationResult(ip=normalized_target, reputation="unavailable", confidence="none", provider="unavailable", checked_at=_now_iso(), reason="provider_disabled")
            normalized_target = validate_hostname_or_ip(target, max_length=max_len)
        except RuntimeError:
            from ..config import get_config as _get_cfg
            cfg = _get_cfg()
            normalized_target = validate_hostname_or_ip(target, max_length=cfg.URL_MAX_LENGTH)
            if not cfg.IP_REPUTATION_ENABLED:
                return ReputationResult(ip=normalized_target, reputation="unavailable", confidence="none", provider="unavailable", checked_at=_now_iso(), reason="provider_disabled")
        except Exception:
            from ..config import get_config as _get_cfg
            cfg = _get_cfg()
            normalized_target = validate_hostname_or_ip(target, max_length=cfg.URL_MAX_LENGTH)
            if not cfg.IP_REPUTATION_ENABLED:
                return ReputationResult(ip=normalized_target, reputation="unavailable", confidence="none", provider="unavailable", checked_at=_now_iso(), reason="provider_disabled")

        # If target is IP, validate directly
        try:
            ipaddress.ip_address(normalized_target)
            # It's an IP
            return IPReputationService.check_ip(normalized_target)
        except ValueError:
            pass

        # Hostname -> resolve to IP
        try:
            info = socket.getaddrinfo(normalized_target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            # Prefer non-link-local
            resolved = None
            for addr in info:
                cand = addr[4][0]
                try:
                    parsed = ipaddress.ip_address(cand)
                    if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved or parsed.is_multicast or parsed.is_unspecified:
                        continue
                    resolved = cand
                    break
                except ValueError:
                    continue
            if resolved is None:
                # All resolved were private or none; use first
                resolved = info[0][4][0] if info else normalized_target
        except socket.gaierror:
            raise ValidationError("Unable to resolve target hostname", details={"field": "target"})

        # Validate resolved IP is not private before sending to provider
        from ..utils.validators import is_private_ip as _is_private_ip
        if _is_private_ip(resolved):
            raise ValidationError(
                "Target resolves to a private or reserved address",
                details={"field": "target"},
            )

        return IPReputationService.check_ip(resolved)
