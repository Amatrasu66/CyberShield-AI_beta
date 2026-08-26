"""
Threat Intelligence Aggregator — provider-independent threat intelligence.

Architecture:
    PortScannerService
        ↓
    ThreatIntelligenceService (aggregator)
        ├── AbuseIPDBProvider
        └── ProjectHoneyPotProvider
                 ↓
            ProviderEvidence[]

Aggregator isolates provider failures, uses per-(ip,provider) cache,
never crashes scan, returns normalized bundle.

Bundle never contains secrets.
"""

from __future__ import annotations

import ipaddress
import socket
from datetime import datetime, timezone
from typing import Optional

from ..config import get_config
from ..errors import ValidationError
from .project_honeypot_provider import ProviderEvidence, ProjectHoneyPotProvider


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _threat_global_enabled() -> bool:
    try:
        from flask import current_app
        v = current_app.config.get("THREAT_INTELLIGENCE_ENABLED")
        if v is not None:
            return bool(v)
    except Exception:
        pass
    try:
        cfg = get_config()
        return bool(getattr(cfg, "THREAT_INTELLIGENCE_ENABLED", False))
    except Exception:
        return False


def _abuseipdb_enabled() -> bool:
    # AbuseIPDB has its own flag; if global is False, still respect per-provider?
    # Global kill switch disables all
    if not _threat_global_enabled():
        # Fall back to legacy IP_REPUTATION_ENABLED alone if global not set?
        # Prompt says THREAT_INTELLIGENCE_ENABLED=false default, PROJECT_HONEYPOT_ENABLED=false
        # Keep AbuseIPDB working even if global false? For backward compat keep abuseipdb enabled via legacy flag
        # But honor global if explicitly false -> disable honeypot only? Let's treat global as optional;
        # if THREAT_INTELLIGENCE_ENABLED is False, aggregator still provides AbuseIPDB via legacy path
        pass
    try:
        from flask import current_app
        enabled = current_app.config.get("IP_REPUTATION_ENABLED")
        if enabled is not None:
            if not enabled:
                return False
            provider = str(current_app.config.get("IP_REPUTATION_PROVIDER", "abuseipdb") or "abuseipdb").strip().lower()
            key = str(current_app.config.get("IP_REPUTATION_API_KEY", "") or "").strip()
            return provider == "abuseipdb" and bool(key)
    except Exception:
        pass
    try:
        cfg = get_config()
        return bool(cfg.IP_REPUTATION_ENABLED) and str(cfg.IP_REPUTATION_PROVIDER).strip().lower() == "abuseipdb" and bool(str(cfg.IP_REPUTATION_API_KEY).strip())
    except Exception:
        return False


def _honeypot_enabled() -> bool:
    try:
        from flask import current_app
        v = current_app.config.get("PROJECT_HONEYPOT_ENABLED")
        if v is not None:
            if not bool(v):
                return False
            key = str(current_app.config.get("PROJECT_HONEYPOT_ACCESS_KEY", "") or "").strip()
            return bool(key)
    except Exception:
        pass
    try:
        cfg = get_config()
        return bool(getattr(cfg, "PROJECT_HONEYPOT_ENABLED", False)) and bool(str(getattr(cfg, "PROJECT_HONEYPOT_ACCESS_KEY", "") or "").strip())
    except Exception:
        return False


def _honeypot_global_gate() -> bool:
    # Global kill switch for honeypot — if THREAT_INTELLIGENCE_ENABLED is False, disable honeypot
    # Prefer Flask config when available (tests, request context)
    try:
        from flask import current_app
        v = current_app.config.get("THREAT_INTELLIGENCE_ENABLED")
        if v is not None:
            return bool(v)
    except Exception:
        pass
    try:
        cfg = get_config()
        if hasattr(cfg, "THREAT_INTELLIGENCE_ENABLED"):
            return bool(getattr(cfg, "THREAT_INTELLIGENCE_ENABLED"))
    except Exception:
        pass
    return False


def _reputation_to_evidence(rep) -> ProviderEvidence:
    """Convert AbuseIPDB ReputationResult -> ProviderEvidence."""
    # rep is ReputationResult dataclass
    checked_at = getattr(rep, "checked_at", None) or _now_iso()
    status = "available" if rep.reputation in ("clean", "suspicious", "malicious") else ("unknown" if rep.reputation == "unknown" else "unavailable")
    return ProviderEvidence(
        ip=rep.ip,
        provider=rep.provider or "abuseipdb",
        status=status,
        reputation=rep.reputation,
        confidence=rep.confidence or "none",
        threat_score=rep.reports,  # abuse reports as threat analogue, keep raw
        visitor_type=None,
        visitor_type_name=None,
        days_since_activity=None,
        last_seen=rep.last_reported_at,
        reason=rep.reason,
        checked_at=checked_at,
        raw={"reports": rep.reports, "country": rep.country, "asn": rep.asn, "organization": rep.organization, "isp": rep.isp},
        malicious=bool(rep.malicious),
        suspicious=bool(rep.suspicious),
        categories=[],
        evidence={"reports": rep.reports, "country": rep.country, "asn": rep.asn, "organization": rep.organization, "isp": rep.isp, "is_whitelisted": rep.reputation == "clean"},
    )


def _evidence_from_cache_row(row, provider: str, ip: str) -> Optional[ProviderEvidence]:
    """Attempt to reconstruct ProviderEvidence from cache row if evidence JSON exists."""
    try:
        # If row contains evidence JSON (new schema), use it
        evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else None
        # Check if honeypot fields present
        if provider == "project_honeypot":
            # evidence may contain honeypot fields
            if evidence is not None:
                return ProviderEvidence(
                    ip=row.get("ip") or ip,
                    provider=provider,
                    status=evidence.get("status") or ("unknown" if row.get("reputation") == "unknown" else "available" if row.get("reputation") in ("suspicious","malicious") else "unavailable"),
                    reputation=row.get("reputation") or "unknown",
                    confidence=row.get("confidence") or "none",
                    threat_score=evidence.get("threat_score") if evidence.get("threat_score") is not None else row.get("threat_score"),
                    visitor_type=evidence.get("visitor_type") if evidence.get("visitor_type") is not None else row.get("visitor_type"),
                    visitor_type_name=evidence.get("visitor_type_name"),
                    days_since_activity=evidence.get("days_since_activity") if evidence.get("days_since_activity") is not None else row.get("days_since_activity"),
                    last_seen=evidence.get("last_seen") or row.get("last_seen"),
                    reason=row.get("reason"),
                    checked_at=row.get("checked_at"),
                    raw=evidence.get("raw") or {},
                    malicious=bool(row.get("malicious")),
                    suspicious=bool(row.get("suspicious")),
                    categories=evidence.get("visitor_type_flags") or evidence.get("categories") or [],
                    evidence=evidence,
                )
        # AbuseIPDB fallback: use reports field etc.
        return None
    except Exception:
        return None


class ThreatIntelligenceService:
    """Aggregator for threat intelligence providers."""

    @staticmethod
    def _get_enabled_providers():
        providers = []
        # AbuseIPDB via legacy service — we keep direct provider for cache isolation
        if _abuseipdb_enabled():
            # We don't need to instantiate here; call via IPReputationService for consistency
            providers.append("abuseipdb")
        # HoneyPot only if global enabled and honeypot enabled
        if _honeypot_global_gate() and _honeypot_enabled():
            providers.append("project_honeypot")
        return providers

    @staticmethod
    def check_ip(ip: str) -> dict:
        """Check threat intelligence for a single validated IP. Returns bundle dict."""
        from ..utils.validators import validate_ip_address, is_private_ip

        normalized = validate_ip_address(ip)
        if is_private_ip(normalized):
            raise ValidationError(
                "Private or reserved IP addresses cannot be checked for reputation",
                details={"field": "ip"},
            )

        # IPv6 handling: HoneyPot will return unavailable individually; AbuseIPDB may handle IPv6 elsewhere
        # Aggregator still processes each provider

        checked_at = _now_iso()
        providers_evidence: list[dict] = []
        errors: list[dict] = []

        enabled = ThreatIntelligenceService._get_enabled_providers()

        if not enabled:
            # No providers enabled -> unavailable bundle
            ev = ProviderEvidence(
                ip=normalized,
                provider="unavailable",
                status="unavailable",
                reputation="unavailable",
                confidence="none",
                reason="all_providers_disabled",
                checked_at=checked_at,
                raw={},
            )
            providers_evidence.append(ev.to_dict())
            bundle = {
                "ip": normalized,
                "checked_at": checked_at,
                "providers": providers_evidence,
                "available_providers": 0,
                "sources_checked": 0,
                "sources_available": 0,
                "confidence": "none",
                "summary": {
                    "overall_reputation": "unavailable",
                    "malicious": False,
                    "suspicious": False,
                    "sources_checked": 0,
                    "sources_available": 0,
                    "last_seen": None,
                },
            }
            return bundle

        # For each enabled provider, try cache then provider
        for prov_name in sorted(enabled):
            ev: Optional[ProviderEvidence] = None
            # Try cache first (per provider)
            try:
                from .ip_reputation_cache_service import IPReputationCacheService
                # AbuseIPDB cache returns ReputationResult; HoneyPot returns ProviderEvidence if extended
                cached = IPReputationCacheService.get(normalized, prov_name)
                if cached is not None:
                    # cached may be ReputationResult or ProviderEvidence
                    if isinstance(cached, ProviderEvidence):
                        ev = cached
                    elif hasattr(cached, "reputation") and hasattr(cached, "provider"):
                        # ReputationResult -> convert
                        ev = _reputation_to_evidence(cached)
                    else:
                        ev = None
                    if ev is not None:
                        providers_evidence.append(ev.to_dict())
                        continue
            except Exception:
                pass

            # Cache miss -> call provider directly (isolated)
            try:
                if prov_name == "abuseipdb":
                    from .ip_reputation_service import IPReputationService
                    # Bypass cache inside IPReputationService to avoid double cache; call provider directly
                    provider = IPReputationService._get_provider()
                    if provider.provider_name == "unavailable":
                        ev = ProviderEvidence(
                            ip=normalized, provider="abuseipdb", status="unavailable", reputation="unavailable",
                            confidence="none", reason="provider_disabled", checked_at=_now_iso(), raw={},
                        )
                    else:
                        # Use provider directly, but need circuit handling similar to IPReputationService.check_ip without cache
                        # Reuse IPReputationService.check_ip for circuit then convert? For aggregator we want isolation
                        # Call provider.check_ip and handle circuit manually? Simpler: call IPReputationService.check_ip but it will attempt cache again (ok)
                        # To avoid recursion, directly call provider
                        from .ip_reputation_service import _circuit_should_block, _circuit_is_failure, _circuit_record_failure, _circuit_record_success, ReputationResult
                        if _circuit_should_block(provider.provider_name):
                            ev = ProviderEvidence(
                                ip=normalized, provider=prov_name, status="unavailable", reputation="unavailable",
                                confidence="none", reason="circuit_open", checked_at=_now_iso(), raw={},
                            )
                        else:
                            rep = provider.check_ip(normalized)
                            # Update circuit
                            try:
                                if _circuit_is_failure(rep):
                                    _circuit_record_failure(provider.provider_name)
                                else:
                                    _circuit_record_success(provider.provider_name)
                            except Exception:
                                pass
                            ev = _reputation_to_evidence(rep)
                            # Cache non-unavailable via cache service (which handles ProviderEvidence/ReputationResult)
                            try:
                                from .ip_reputation_cache_service import IPReputationCacheService
                                # Put original rep (cache service handles ReputationResult)
                                IPReputationCacheService.put(rep)
                            except Exception:
                                pass
                elif prov_name == "project_honeypot":
                    provider = ProjectHoneyPotProvider()
                    ev = provider.check_ip(normalized)
                    # Cache via extended cache (supports ProviderEvidence)
                    try:
                        from .ip_reputation_cache_service import IPReputationCacheService
                        IPReputationCacheService.put(ev)
                    except Exception:
                        pass
                else:
                    ev = ProviderEvidence(
                        ip=normalized, provider=prov_name, status="unavailable", reputation="unavailable",
                        confidence="none", reason="unknown_provider", checked_at=_now_iso(), raw={},
                    )
            except Exception as exc:
                ev = ProviderEvidence(
                    ip=normalized, provider=prov_name, status="unavailable", reputation="unavailable",
                    confidence="none", reason="provider_error", checked_at=_now_iso(), raw={"error": type(exc).__name__},
                )
                errors.append({"provider": prov_name, "reason": "provider_error"})

            if ev is not None:
                providers_evidence.append(ev.to_dict())
            else:
                # Ensure at least an unavailable entry
                fallback = ProviderEvidence(
                    ip=normalized, provider=prov_name, status="unavailable", reputation="unavailable",
                    confidence="none", reason="provider_error", checked_at=_now_iso(), raw={},
                )
                providers_evidence.append(fallback.to_dict())

        # Build summary
        # Filter unavailable for worst-of
        usable = [p for p in providers_evidence if p.get("reputation") != "unavailable"]
        rank = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0, "unavailable": -1}
        overall = "unknown"
        if not usable:
            overall = "unavailable"
        else:
            worst = max(usable, key=lambda x: rank.get(x.get("reputation", "unknown"), -1))
            overall = worst.get("reputation", "unknown")

        sources_available = sum(1 for p in providers_evidence if p.get("reputation") != "unavailable")
        malicious = any(p.get("malicious") for p in providers_evidence)
        suspicious = any(p.get("suspicious") for p in providers_evidence)

        # Evidence completeness confidence: high if any usable, medium if all unavailable, low if no providers?
        if sources_available > 0:
            # If any provider has usable reputation (clean/suspicious/malicious/unknown) -> high
            has_usable = any(p.get("reputation") in ("clean", "suspicious", "malicious", "unknown") for p in providers_evidence)
            bundle_confidence = "high" if has_usable else "medium"
        else:
            bundle_confidence = "medium" if providers_evidence else "none"

        # Last seen most recent
        last_seen_vals = [p.get("last_seen") for p in providers_evidence if p.get("last_seen")]
        last_seen = max(last_seen_vals) if last_seen_vals else None

        # Highest provider confidence for summary
        conf_rank = {"none": 0, "low": 1, "medium": 2, "high": 3, "very_high": 4}
        max_conf = "none"
        max_rank = -1
        for p in providers_evidence:
            c = str(p.get("confidence") or "none").lower()
            r = conf_rank.get(c, 0)
            if r > max_rank:
                max_rank = r
                max_conf = c

        bundle = {
            "ip": normalized,
            "checked_at": checked_at,
            "providers": providers_evidence,
            "available_providers": sources_available,
            "sources_checked": len(enabled),
            "sources_available": sources_available,
            "confidence": bundle_confidence,
            "summary": {
                "overall_reputation": overall,
                "evidence_confidence": max_conf,
                "malicious": malicious,
                "suspicious": suspicious,
                "sources_checked": len(enabled),
                "sources_available": sources_available,
                "last_seen": last_seen,
            },
            "errors": errors,
        }
        return bundle

    @staticmethod
    def check_target(target: str) -> dict:
        """Resolve hostname to IP then check intelligence."""
        from ..utils.validators import validate_hostname_or_ip
        try:
            from flask import current_app
            max_len = current_app.config.get("URL_MAX_LENGTH", 2048)
        except Exception:
            max_len = get_config().URL_MAX_LENGTH
        normalized_target = validate_hostname_or_ip(target, max_length=max_len)
        # If IP literal
        try:
            ipaddress.ip_address(normalized_target)
            return ThreatIntelligenceService.check_ip(normalized_target)
        except ValueError:
            pass
        # Hostname resolve
        try:
            info = socket.getaddrinfo(normalized_target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
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
                resolved = info[0][4][0] if info else normalized_target
        except socket.gaierror:
            raise ValidationError("Unable to resolve target hostname", details={"field": "target"})
        from ..utils.validators import is_private_ip as _is_private_ip
        if _is_private_ip(resolved):
            raise ValidationError("Target resolves to a private or reserved address", details={"field": "target"})
        return ThreatIntelligenceService.check_ip(resolved)


# Alias for design doc
ThreatIntelligenceAggregator = ThreatIntelligenceService
