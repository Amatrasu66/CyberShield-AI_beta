"""
IP Reputation Cache Service (bounded, shared).

Shared cache table `ip_reputation_cache` stores normalized results keyed by
(ip, provider). No user_id, no API keys, no tokens. Expires after
IP_REPUTATION_CACHE_TTL seconds.

Access is via service-role client (bypasses RLS) so frontend cannot
manipulate it. Falls back to user-scoped client if admin not configured
(tests).
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Optional

from ..config import get_config
from ..database import get_user_supabase_client

def _log_safe(msg: str, extra: dict | None = None):
    """Log safe diagnostic without secrets."""
    try:
        from flask import current_app
        logger = getattr(current_app, "logger", None)
        if logger is not None:
            safe_extra = {k: v for k, v in (extra or {}).items()
                          if "key" not in k.lower() and "token" not in k.lower() and "auth" not in k.lower()}
            logger.info(f"[ip_reputation_cache] {msg} {safe_extra}")
            return
    except RuntimeError:
        pass
    except Exception:
        pass
    try:
        import logging
        logging.getLogger("ip_reputation_cache").info(f"{msg} {extra or {}}")
    except Exception:
        pass

try:
    from ..database.supabase_client import get_supabase_admin_client, get_supabase_client
except ImportError:
    get_supabase_admin_client = None
    get_supabase_client = None


def _get_cache_client():
    """Return a Supabase client capable of accessing the shared cache.

    Strictly prefers service_role (admin) which bypasses RLS on the shared
    cache. Frontend must never access this table directly.
    """
    # 1. Try admin via factory (uses get_config)
    if get_supabase_admin_client is not None:
        try:
            client = get_supabase_admin_client()
            if client is not None:
                return client
        except Exception as exc:
            _log_safe("cache_admin_client_error", extra={"error_type": type(exc).__name__})
    # 2. Try building directly from Flask current_app config (handles Render env and tests)
    try:
        from flask import current_app
        # current_app is available when inside app/request context; check config directly
        url = current_app.config.get("SUPABASE_URL")
        # Prefer SUPABASE_SECRET_KEY, fallback to SERVICE_ROLE
        key = current_app.config.get("SUPABASE_SECRET_KEY") or current_app.config.get("SUPABASE_SERVICE_ROLE_KEY")
        if url and key:
            from supabase import create_client
            try:
                return create_client(url.strip(), key.strip())
            except Exception as exc:
                _log_safe("cache_direct_admin_failed", extra={"error_type": type(exc).__name__})
    except RuntimeError:
        pass
    except Exception as exc:
        _log_safe("cache_direct_admin_error", extra={"error_type": type(exc).__name__})
    # 3. Final fallback: try anon (will be blocked by RLS, but keep for local dev without secret)
    # We do not log as error here; cache will be treated as miss.
    if get_supabase_client is not None:
        try:
            client = get_supabase_client()
            if client is not None:
                # This client will be denied by RLS (no policies) — use only if admin truly unavailable in dev
                # Log that we are falling back, but don't hide it
                _log_safe("cache_fallback_anon", extra={})
                return client
        except Exception:
            pass
    _log_safe("cache_admin_unavailable", extra={"reason": "service_role_not_configured"})
    return None


def _cache_enabled() -> bool:
    try:
        from flask import current_app
        val = current_app.config.get("IP_REPUTATION_CACHE_ENABLED")
        if val is not None:
            return bool(val)
    except RuntimeError:
        pass
    except Exception:
        pass
    cfg = get_config()
    return bool(cfg.IP_REPUTATION_CACHE_ENABLED)


def _cache_ttl() -> int:
    try:
        from flask import current_app
        val = current_app.config.get("IP_REPUTATION_CACHE_TTL")
        if val is not None:
            return int(val)
    except RuntimeError:
        pass
    except Exception:
        pass
    cfg = get_config()
    return int(cfg.IP_REPUTATION_CACHE_TTL)


def _parse_ts(value) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    try:
        s = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


class IPReputationCacheService:
    """Small cache layer for normalized ReputationResult rows."""

    @staticmethod
    def get(ip: str, provider: str):
        """Return cached ReputationResult if fresh else None.

        Never raises; returns None on miss/expired/unavailable.
        """
        if not _cache_enabled():
            _log_safe("cache_get_skipped_disabled", extra={"ip": ip, "provider": provider})
            return None
        # Validation already done by caller, but guard
        if not ip or not provider:
            return None
        client = _get_cache_client()
        if client is None:
            _log_safe("cache_get_no_client", extra={"ip": ip, "provider": provider})
            return None
        try:
            result = (
                client.table("ip_reputation_cache")
                .select("*")
                .eq("ip", ip)
                .eq("provider", provider)
                .execute()
            )
            data = result.get("data") if isinstance(result, dict) else getattr(result, "data", None)
            rows = data or []
            if not rows:
                _log_safe("cache_miss", extra={"ip": ip, "provider": provider})
                return None
            row = rows[0] if isinstance(rows, list) else rows
            expires_at = _parse_ts(row.get("expires_at"))
            if expires_at is None:
                _log_safe("cache_miss_no_expiry", extra={"ip": ip, "provider": provider})
                return None
            now = datetime.now(timezone.utc)
            if expires_at <= now:
                # Expired — treat as miss but keep row for diagnostic until overwritten
                _log_safe("cache_expired", extra={"ip": ip, "provider": provider, "expired": True})
                return None
            _log_safe("cache_hit", extra={"ip": ip, "provider": provider})
            # Convert to ReputationResult
            from .ip_reputation_service import ReputationResult
            return ReputationResult(
                ip=row.get("ip") or ip,
                reputation=row.get("reputation") or "unknown",
                confidence=row.get("confidence") or "none",
                malicious=bool(row.get("malicious")),
                suspicious=bool(row.get("suspicious")),
                reports=int(row.get("reports") or 0),
                country=row.get("country"),
                asn=_parse_asn(row.get("asn")),
                organization=row.get("organization"),
                isp=row.get("isp"),
                last_reported_at=row.get("last_reported_at"),
                provider=row.get("provider") or provider,
                checked_at=row.get("checked_at"),
                reason=None,
            )
        except Exception as exc:
            # Cache must never break caller
            _log_safe("cache_get_error", extra={"ip": ip, "provider": provider, "error_type": type(exc).__name__})
            return None

    @staticmethod
    def put(result) -> None:
        """Upsert a fresh result into cache.

        Skips caching if disabled or result is unavailable or missing fields.
        Uses (ip, provider) unique constraint via upsert.
        """
        if not _cache_enabled():
            _log_safe("cache_put_skipped_disabled", extra={"ip": getattr(result, "ip", None), "provider": getattr(result, "provider", None) if result else None})
            return
        if result is None:
            return
        # Do not cache unavailable results (missing key, auth failure, etc.)
        if getattr(result, "reputation", None) == "unavailable":
            _log_safe("cache_put_skipped_unavailable", extra={"ip": getattr(result, "ip", None), "provider": getattr(result, "provider", None)})
            return
        ip = getattr(result, "ip", None)
        provider = getattr(result, "provider", None)
        if not ip or not provider:
            _log_safe("cache_put_missing_key", extra={})
            return
        client = _get_cache_client()
        if client is None:
            _log_safe("cache_put_no_client", extra={"ip": ip, "provider": provider})
            return
        try:
            now = datetime.now(timezone.utc)
            ttl = _cache_ttl()
            checked_at = _parse_ts(getattr(result, "checked_at", None)) or now
            expires_at = checked_at + timedelta(seconds=ttl)
            # Ensure checked_at is iso
            if isinstance(checked_at, datetime):
                checked_at_iso = checked_at.isoformat()
            else:
                checked_at_iso = now.isoformat()
            payload = {
                "ip": ip,
                "reputation": result.reputation,
                "confidence": result.confidence or "none",
                "malicious": bool(result.malicious),
                "suspicious": bool(result.suspicious),
                "reports": int(result.reports or 0),
                "country": result.country,
                "asn": str(result.asn) if result.asn is not None else None,
                "organization": result.organization,
                "isp": result.isp,
                "last_reported_at": result.last_reported_at,
                "provider": provider,
                "checked_at": checked_at_iso,
                "expires_at": expires_at.isoformat(),
                "updated_at": now.isoformat(),
            }
            # Try upsert with on_conflict; fake may not support on_conflict param
            success = False
            last_error: Exception | None = None
            try:
                client.table("ip_reputation_cache").upsert(payload, on_conflict="ip,provider").execute()
                success = True
            except TypeError as exc:
                last_error = exc
                # Fallback for fake that doesn't accept on_conflict kw
                try:
                    client.table("ip_reputation_cache").upsert(payload).execute()
                    success = True
                    last_error = None
                except Exception as exc2:
                    last_error = exc2
                    # Last fallback: try insert then update
                    try:
                        client.table("ip_reputation_cache").insert(payload).execute()
                        success = True
                        last_error = None
                    except Exception as exc3:
                        last_error = exc3
                        # Maybe unique violation, try update
                        try:
                            (
                                client.table("ip_reputation_cache")
                                .update(payload)
                                .eq("ip", ip)
                                .eq("provider", provider)
                                .execute()
                            )
                            success = True
                            last_error = None
                        except Exception as exc4:
                            last_error = exc4
            except Exception as exc:
                last_error = exc
                # Try alternative without on_conflict
                try:
                    client.table("ip_reputation_cache").upsert(payload).execute()
                    success = True
                    last_error = None
                except Exception as exc2:
                    last_error = exc2
            if success:
                _log_safe("cache_put_success", extra={"ip": ip, "provider": provider})
            else:
                _log_safe("cache_put_failed", extra={"ip": ip, "provider": provider, "error_type": type(last_error).__name__ if last_error else "unknown"})
                # Also log sanitized message if not containing secrets
                try:
                    import logging
                    logging.getLogger("ip_reputation_cache").warning(f"cache put failed for {ip}/{provider}: {type(last_error).__name__}")
                except Exception:
                    pass
        except Exception as exc:
            # Never let cache write break caller
            _log_safe("cache_put_error", extra={"ip": ip, "provider": provider, "error_type": type(exc).__name__})
            return


def _parse_asn(value):
    if value is None or value == "":
        return None
    try:
        s = str(value).strip().replace("AS", "").replace("as", "")
        return int(s)
    except Exception:
        return None
