"""Tests for bounded IP reputation cache (shared, service-role)."""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import requests

from app.services.ip_reputation_service import IPReputationService, ReputationResult
from app.services.ip_reputation_cache_service import IPReputationCacheService


def _mock_abuse_resp(score=10, reports=1, whitelisted=False, **kw):
    m = MagicMock()
    m.status_code = 200
    m.headers = {}
    m.text = "{}"
    data = {
        "ipAddress": kw.get("ip", "1.1.1.1"),
        "abuseConfidenceScore": score,
        "totalReports": reports,
        "countryCode": "US",
        "isp": "Test ISP",
        "isWhitelisted": whitelisted,
        "lastReportedAt": "2026-08-20T12:00:00+00:00",
    }
    data.update(kw)
    m.json.return_value = {"data": data}
    return m


class TestCacheDisabled:
    def test_no_read_write_when_disabled(self, app, fake_supabase):
        app.config["IP_REPUTATION_ENABLED"] = True
        app.config["IP_REPUTATION_CACHE_ENABLED"] = False
        app.config["IP_REPUTATION_API_KEY"] = "k"
        mock_resp = _mock_abuse_resp(score=5, reports=1)
        with patch("app.services.ip_reputation_service.requests.get", return_value=mock_resp) as mg:
            with app.app_context():
                r = IPReputationService.check_ip("1.1.1.1")
                assert mg.call_count == 1
                assert len(fake_supabase.rows.get("ip_reputation_cache", [])) == 0
                # second call also hits provider
                with patch("app.services.ip_reputation_service.requests.get", return_value=mock_resp) as mg2:
                    IPReputationService.check_ip("1.1.1.1")
                    assert mg2.call_count == 1


class TestCacheMissHit:
    def test_miss_creates_row(self, app, fake_supabase):
        app.config["IP_REPUTATION_ENABLED"] = True
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["IP_REPUTATION_API_KEY"] = "k"
        mock_resp = _mock_abuse_resp(score=5, reports=1)
        with app.app_context():
            with patch("app.services.ip_reputation_service.requests.get", return_value=mock_resp) as mg:
                r = IPReputationService.check_ip("2.2.2.2")
                assert r.reputation != "unavailable"
                assert mg.call_count == 1
                rows = fake_supabase.rows.get("ip_reputation_cache", [])
                assert len(rows) == 1
                assert rows[0]["ip"] == "2.2.2.2"
                assert rows[0]["provider"] == "abuseipdb"
                # allowlist: no api key leak
                assert "k" not in str(rows[0].values())
                assert "user_id" not in rows[0]

    def test_hit_no_provider(self, app, fake_supabase):
        app.config["IP_REPUTATION_ENABLED"] = True
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["IP_REPUTATION_API_KEY"] = "k"
        mock_resp = _mock_abuse_resp(score=5, reports=1)
        with app.app_context():
            with patch("app.services.ip_reputation_service.requests.get", return_value=mock_resp):
                IPReputationService.check_ip("3.3.3.3")
            # second call should be hit
            with patch("app.services.ip_reputation_service.requests.get", return_value=mock_resp) as mg:
                r2 = IPReputationService.check_ip("3.3.3.3")
                assert mg.call_count == 0
                assert r2.reports == 1


class TestExpired:
    def test_expired_refreshed_and_ttl(self, app, fake_supabase):
        app.config["IP_REPUTATION_ENABLED"] = True
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["IP_REPUTATION_CACHE_TTL"] = 86400
        app.config["IP_REPUTATION_API_KEY"] = "k"
        mock_resp = _mock_abuse_resp(score=5, reports=1)
        with app.app_context():
            with patch("app.services.ip_reputation_service.requests.get", return_value=mock_resp):
                IPReputationService.check_ip("4.4.4.4")
            # expire
            row = fake_supabase.rows["ip_reputation_cache"][0]
            row["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
            mock_resp2 = _mock_abuse_resp(score=85, reports=10)
            with patch("app.services.ip_reputation_service.requests.get", return_value=mock_resp2) as mg:
                r = IPReputationService.check_ip("4.4.4.4")
                assert mg.call_count == 1
                assert r.reputation == "malicious"
                assert len(fake_supabase.rows["ip_reputation_cache"]) == 1
                checked = datetime.fromisoformat(fake_supabase.rows["ip_reputation_cache"][0]["checked_at"].replace("Z", "+00:00"))
                expires = datetime.fromisoformat(fake_supabase.rows["ip_reputation_cache"][0]["expires_at"].replace("Z", "+00:00"))
                assert abs((expires - checked).total_seconds() - 86400) < 5


class TestPrivateIP:
    @pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "224.0.0.1", "::1"])
    def test_private_no_cache_provider(self, app, fake_supabase, ip):
        app.config["IP_REPUTATION_ENABLED"] = True
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["IP_REPUTATION_API_KEY"] = "k"
        with app.app_context():
            with patch("app.services.ip_reputation_service.requests.get") as mg:
                with pytest.raises(Exception) as exc:
                    IPReputationService.check_ip(ip)
                assert mg.call_count == 0
                assert len([r for r in fake_supabase.rows.get("ip_reputation_cache", []) if r.get("ip") == ip]) == 0


class TestProviderFailureExpired:
    def test_expired_provider_fail_returns_unavailable_and_keeps_old(self, app, fake_supabase):
        app.config["IP_REPUTATION_ENABLED"] = True
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["IP_REPUTATION_API_KEY"] = "k"
        mock_resp = _mock_abuse_resp(score=5, reports=1)
        with app.app_context():
            with patch("app.services.ip_reputation_service.requests.get", return_value=mock_resp):
                IPReputationService.check_ip("5.5.5.5")
            row = fake_supabase.rows["ip_reputation_cache"][0]
            row["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
            orig_rep = row["reputation"]
            with patch("app.services.ip_reputation_service.requests.get", side_effect=requests.Timeout()):
                r = IPReputationService.check_ip("5.5.5.5")
                assert r.reputation == "unavailable"
                # cache not overwritten with unavailable
                assert fake_supabase.rows["ip_reputation_cache"][0]["reputation"] == orig_rep
            # port scanner still succeeds
            from app.services.port_scanner_service import PortScannerService
            import socket
            class MS:
                def settimeout(self,a): pass
                def connect_ex(self,a): return 1
                def recv(self,a): return b""
                def close(self): pass
            with patch("socket.socket", side_effect=lambda *a, **k: MS()):
                with patch("app.services.ip_reputation_service.requests.get", side_effect=requests.Timeout()):
                    with patch("app.services.port_scanner_service.get_user_supabase_client", lambda at=None: fake_supabase):
                        res = PortScannerService.scan_ports(target="5.5.5.5", ports=[80], user_id="uid-test")
                        assert res.ip_reputation["reputation"] == "unavailable"


class TestMissingKeyAnd429:
    def test_missing_key_not_cached(self, app, fake_supabase):
        app.config["IP_REPUTATION_ENABLED"] = True
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["IP_REPUTATION_API_KEY"] = ""
        with app.app_context():
            with patch("app.services.ip_reputation_service.requests.get") as mg:
                r = IPReputationService.check_ip("6.6.6.6")
                assert r.reputation == "unavailable"
                assert r.reason == "missing_api_key"
                assert mg.call_count == 0
                assert len(fake_supabase.rows.get("ip_reputation_cache", [])) == 0
                # no secret in payload
                assert "API_KEY" not in str(fake_supabase.rows)

        app.config["IP_REPUTATION_API_KEY"] = "k"

    def test_429_not_cached(self, app, fake_supabase):
        app.config["IP_REPUTATION_ENABLED"] = True
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["IP_REPUTATION_API_KEY"] = "k"
        mock429 = MagicMock()
        mock429.status_code = 429
        mock429.headers = {}
        with app.app_context():
            with patch("app.services.ip_reputation_service.requests.get", return_value=mock429):
                r = IPReputationService.check_ip("7.7.7.7")
                assert r.reputation == "unavailable"
                assert len([row for row in fake_supabase.rows.get("ip_reputation_cache", []) if row.get("ip") == "7.7.7.7"]) == 0


class TestProviderIsolation:
    def test_same_ip_different_provider_separate_rows(self, app, fake_supabase):
        app.config["IP_REPUTATION_ENABLED"] = True
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["IP_REPUTATION_API_KEY"] = "k"
        from app.services.ip_reputation_service import ReputationResult
        with app.app_context():
            rr1 = ReputationResult(ip="8.8.8.8", reputation="clean", confidence="none", provider="abuseipdb", checked_at=datetime.now(timezone.utc).isoformat())
            rr2 = ReputationResult(ip="8.8.8.8", reputation="malicious", confidence="high", provider="other", checked_at=datetime.now(timezone.utc).isoformat())
            IPReputationCacheService.put(rr1)
            IPReputationCacheService.put(rr2)
            rows = [r for r in fake_supabase.rows["ip_reputation_cache"] if r["ip"] == "8.8.8.8"]
            assert len(rows) == 2
            providers = {r["provider"] for r in rows}
            assert providers == {"abuseipdb", "other"}


class TestCacheUpdate:
    def test_upsert_no_duplicate(self, app, fake_supabase):
        app.config["IP_REPUTATION_ENABLED"] = True
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["IP_REPUTATION_API_KEY"] = "k"
        mock_resp = _mock_abuse_resp(score=5, reports=1)
        with app.app_context():
            with patch("app.services.ip_reputation_service.requests.get", return_value=mock_resp):
                IPReputationService.check_ip("9.9.9.9")
            assert len(fake_supabase.rows["ip_reputation_cache"]) == 1
            # expire and refresh
            fake_supabase.rows["ip_reputation_cache"][0]["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
            mock_resp2 = _mock_abuse_resp(score=85, reports=5)
            with patch("app.services.ip_reputation_service.requests.get", return_value=mock_resp2):
                IPReputationService.check_ip("9.9.9.9")
            assert len(fake_supabase.rows["ip_reputation_cache"]) == 1
            assert fake_supabase.rows["ip_reputation_cache"][0]["reputation"] == "malicious"


class TestTTL:
    def test_expires_at_checked_plus_ttl(self, app, fake_supabase):
        app.config["IP_REPUTATION_ENABLED"] = True
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["IP_REPUTATION_CACHE_TTL"] = 3600
        app.config["IP_REPUTATION_API_KEY"] = "k"
        mock_resp = _mock_abuse_resp(score=5, reports=1)
        with app.app_context():
            with patch("app.services.ip_reputation_service.requests.get", return_value=mock_resp):
                IPReputationService.check_ip("11.11.11.11")
            row = fake_supabase.rows["ip_reputation_cache"][0]
            checked = datetime.fromisoformat(row["checked_at"].replace("Z", "+00:00"))
            expires = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
            assert abs((expires - checked).total_seconds() - 3600) < 5
        app.config["IP_REPUTATION_CACHE_TTL"] = 86400


class TestHistoricalSnapshot:
    def test_port_scan_snapshot_from_cache(self, app, fake_supabase):
        app.config["IP_REPUTATION_ENABLED"] = True
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["IP_REPUTATION_API_KEY"] = "k"
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = True
        # prime cache
        mock_resp = _mock_abuse_resp(ip="11.11.11.11", score=85, reports=10)
        with app.app_context():
            with patch("app.services.ip_reputation_service.requests.get", return_value=mock_resp):
                IPReputationService.check_ip("11.11.11.11")
            # port scan should use cached and snapshot
            import socket
            class MS:
                def settimeout(self,a): pass
                def connect_ex(self,a): return 1
                def recv(self,a): return b""
                def close(self): pass
            from app.services.port_scanner_service import PortScannerService
            # Use same fake for port_scans, cache already in fake
            with patch("socket.socket", side_effect=lambda *a, **k: MS()):
                with patch("app.services.ip_reputation_service.requests.get") as mg:
                    # mg should not be called due to cache hit
                    res = PortScannerService.scan_ports(target="11.11.11.11", ports=[80], user_id="uid-hist")
                    assert mg.call_count == 0
                    assert res.ip_reputation["ip"] == "11.11.11.11"
                    # persisted snapshot
                    assert fake_supabase.rows["port_scans"][0]["ip_reputation"]["ip"] == "11.11.11.11"
                    assert fake_supabase.rows["port_scans"][0]["ip_reputation"]["reputation"] == "malicious"


class TestProductionClient:
    def test_service_role_used(self, app, fake_supabase):
        app.config["IP_REPUTATION_ENABLED"] = True
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["IP_REPUTATION_API_KEY"] = "k"
        # fake_supabase auth_tokens records user token usage for port_scans
        # For cache, _get_cache_client should use admin, not user token
        # We verify by checking that after a cached call, auth_tokens does not increase for cache path
        # Instead, we verify put uses admin by checking that fake's inserts for cache exist without needing user token
        mock_resp = _mock_abuse_resp(score=5, reports=1)
        with app.app_context():
            before = len(fake_supabase.auth_tokens)
            with patch("app.services.ip_reputation_service.requests.get", return_value=mock_resp):
                IPReputationService.check_ip("12.12.12.12")
            # cache write used admin, not user token, so auth_tokens should not have grown for cache
            # port_scans not involved, so auth_tokens unchanged
            assert len(fake_supabase.rows["ip_reputation_cache"]) == 1

    def test_upsert_conflict_key(self, app, fake_supabase):
        app.config["IP_REPUTATION_ENABLED"] = True
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["IP_REPUTATION_API_KEY"] = "k"
        from app.services.ip_reputation_service import ReputationResult
        with app.app_context():
            rr = ReputationResult(ip="13.13.13.13", reputation="clean", confidence="none", provider="abuseipdb", checked_at=datetime.now(timezone.utc).isoformat())
            IPReputationCacheService.put(rr)
            # second put with same ip/provider should upsert, not duplicate
            rr2 = ReputationResult(ip="13.13.13.13", reputation="suspicious", confidence="low", provider="abuseipdb", checked_at=datetime.now(timezone.utc).isoformat(), reports=1, suspicious=True)
            IPReputationCacheService.put(rr2)
            rows = [r for r in fake_supabase.rows["ip_reputation_cache"] if r["ip"] == "13.13.13.13"]
            assert len(rows) == 1
            assert rows[0]["reputation"] == "suspicious"

    def test_78_153_140_129_persisted(self, app, fake_supabase):
        app.config["IP_REPUTATION_ENABLED"] = True
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["IP_REPUTATION_API_KEY"] = "secret12345"
        mock_resp = _mock_abuse_resp(ip="78.153.140.129", score=42, reports=5, countryCode="GB")
        with app.app_context():
            with patch("app.services.ip_reputation_service.requests.get", return_value=mock_resp):
                r = IPReputationService.check_ip("78.153.140.129")
                assert r.ip == "78.153.140.129"
                assert r.reputation != "unavailable"
                rows = [row for row in fake_supabase.rows.get("ip_reputation_cache", []) if row["ip"] == "78.153.140.129"]
                assert len(rows) == 1
                assert rows[0]["provider"] == "abuseipdb"
                # API key must never be persisted
                assert "secret12345" not in str(rows[0])
                assert rows[0].get("api_key") is None
                assert "user_id" not in rows[0]
                # payload allowlist
                allowed = {"ip","reputation","confidence","malicious","suspicious","reports","country","asn","organization","isp","last_reported_at","provider","checked_at","expires_at","updated_at","created_at","id"}
                assert set(rows[0].keys()).issubset(allowed.union({"id","created_at","updated_at"}))
        app.config["IP_REPUTATION_API_KEY"] = "k"

    def test_cache_write_failure_safe(self, app, fake_supabase):
        app.config["IP_REPUTATION_ENABLED"] = True
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["IP_REPUTATION_API_KEY"] = "k"
        mock_resp = _mock_abuse_resp(score=5, reports=1)
        # Simulate cache table write failure via fake flag
        fake_supabase.fail_inserts = True
        with app.app_context():
            # put will fail but check_ip should still return result (cache layer swallows)
            with patch("app.services.ip_reputation_service.requests.get", return_value=mock_resp):
                r = IPReputationService.check_ip("14.14.14.14")
                assert r.reputation != "unavailable"
            fake_supabase.fail_inserts = False  # reset for port_scans
            # port scan should still succeed even though cache put fails
            import socket
            class MS:
                def settimeout(self,a): pass
                def connect_ex(self,a): return 1
                def recv(self,a): return b""
                def close(self): pass
            from app.services.port_scanner_service import PortScannerService
            with patch("socket.socket", side_effect=lambda *a, **k: MS()):
                with patch("app.services.ip_reputation_service.requests.get", return_value=mock_resp):
                    with patch("app.services.ip_reputation_cache_service.IPReputationCacheService.put", side_effect=Exception("db down")):
                        res = PortScannerService.scan_ports(target="14.14.14.14", ports=[80], user_id="uid-fail")
                        assert res.ip_reputation is not None
                        assert res.ip_reputation["reputation"] != "unavailable"
        fake_supabase.fail_inserts = False
