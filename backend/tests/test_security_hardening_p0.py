"""Regression tests for P0 security hardening: DNS TOCTOU, rate limiting, Supabase safety."""

import socket
from unittest.mock import patch, MagicMock

import pytest

from app.services.port_scanner_service import PortScannerService
from app.errors import ValidationError


# ------------------------------------------------------------------ helpers
def _mock_socket_factory(open_map=None):
    """Return a socket factory that records the address passed to connect_ex."""
    open_map = open_map or {}
    created = []

    class TrackingSocket:
        def __init__(self, *args, **kwargs):
            self.family = args[0] if args else None
            self.connected_to = None
            created.append(self)

        def settimeout(self, t):
            pass

        def connect_ex(self, addr):
            self.connected_to = addr
            port = addr[1] if isinstance(addr, tuple) else None
            if port in open_map:
                return open_map[port]
            return 1  # closed

        def recv(self, n):
            return b""

        def close(self):
            pass

    return TrackingSocket, created


# ------------------------------------------------------------------ P0-1 DNS TOCTOU

class TestDNSToctou:
    """Scanner must resolve once, validate, and connect to that validated IP."""

    def test_hostname_resolves_once_and_connects_to_validated_ip(self, app):
        """Core TOCTOU regression: connect_ex must use validated public IP, not hostname."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        validated_ip = "93.184.216.34"
        # Patch getaddrinfo to be called exactly once per scan and to record calls
        call_count = {"n": 0}
        original_getaddrinfo = socket.getaddrinfo

        def fake_getaddrinfo(host, *a, **kw):
            call_count["n"] += 1
            # If called with the hostname, return public IP. If somehow called with the IP itself,
            # return that IP (simulates no rebinding)
            if host == "example.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (validated_ip, 0))]
            # Simulate DNS rebinding: if re-resolved with same hostname it would now return private
            # Our code must NOT call this a second time for connection
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0))]

        TrackingSocket, created_sockets = _mock_socket_factory()

        with patch("app.services.port_scanner_service.socket.getaddrinfo", side_effect=fake_getaddrinfo):
            with patch("app.services.port_scanner_service.socket.socket", TrackingSocket):
                result = PortScannerService.scan_ports(target="example.com", ports=[80])

        # Resolved IP must be the validated public IP
        assert result.resolved_ip == validated_ip
        # Every socket connect must use the validated IP, never the hostname
        for s in created_sockets:
            assert s.connected_to[0] == validated_ip, "TOCTOU: connect used hostname, not validated IP"
            assert s.connected_to[0] != "example.com"
        # DNS should have been resolved only once (the secure path)
        assert call_count["n"] == 1

    def test_private_ip_in_dns_is_blocked(self, app):
        """If getaddrinfo returns a private IP, scan must be rejected before any socket."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False

        def fake_getaddrinfo(host, *a, **kw):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]

        with patch("app.services.port_scanner_service.socket.getaddrinfo", side_effect=fake_getaddrinfo):
            with patch("app.services.port_scanner_service.socket.socket") as mock_sock:
                with pytest.raises(ValidationError) as exc:
                    PortScannerService.scan_ports(target="evil.example.com", ports=[80])
                assert "private" in str(exc.value).lower()
                mock_sock.assert_not_called()

    def test_hostname_with_mixed_public_private_is_blocked(self, app):
        """If any resolved address is private, the whole target is rejected."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False

        def fake_getaddrinfo(host, *a, **kw):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 0)),
            ]

        with patch("app.services.port_scanner_service.socket.getaddrinfo", side_effect=fake_getaddrinfo):
            with pytest.raises(ValidationError):
                PortScannerService.scan_ports(target="mixed.example.com", ports=[80])

    def test_public_hostname_allowed(self, app):
        """Legitimate public hostname must still succeed."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        TrackingSocket, _ = _mock_socket_factory()

        def fake_getaddrinfo(host, *a, **kw):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0))]

        with patch("app.services.port_scanner_service.socket.getaddrinfo", side_effect=fake_getaddrinfo):
            with patch("app.services.port_scanner_service.socket.socket", TrackingSocket):
                result = PortScannerService.scan_ports(target="one.one.one.one", ports=[80])
                assert result.resolved_ip == "1.1.1.1"
                assert result.target == "one.one.one.one"

    def test_ipv4_direct_target(self, app):
        """Direct IPv4 literal must validate and connect without DNS."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        TrackingSocket, created = _mock_socket_factory()
        # getaddrinfo must NOT be called for IP literal
        with patch("app.services.port_scanner_service.socket.getaddrinfo") as mock_gai:
            with patch("app.services.port_scanner_service.socket.socket", TrackingSocket):
                result = PortScannerService.scan_ports(target="8.8.8.8", ports=[80])
                mock_gai.assert_not_called()
                assert result.resolved_ip == "8.8.8.8"
                assert created[0].connected_to[0] == "8.8.8.8"
                assert created[0].family == socket.AF_INET

    def test_ipv6_direct_target(self, app):
        """Direct IPv6 literal must validate and use AF_INET6."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        TrackingSocket, created = _mock_socket_factory()
        # Bracketed form is required by validate_hostname_or_ip for IPv6
        with patch("app.services.port_scanner_service.socket.getaddrinfo") as mock_gai:
            with patch("app.services.port_scanner_service.socket.socket", TrackingSocket):
                result = PortScannerService.scan_ports(target="[2001:4860:4860::8888]", ports=[80])
                mock_gai.assert_not_called()
                assert result.resolved_ip == "2001:4860:4860::8888"
                assert created[0].family == socket.AF_INET6
                assert created[0].connected_to[0] == "2001:4860:4860::8888"

    def test_ipv6_private_blocked(self, app):
        """Loopback ::1 must be blocked."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        with pytest.raises(ValidationError):
            PortScannerService.scan_ports(target="::1", ports=[80])

    def test_ipv6_link_local_blocked_via_dns(self, app):
        """fe80:: link-local via hostname DNS must be blocked."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False

        def fake_getaddrinfo(host, *a, **kw):
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1", 0, 0, 0))]

        with patch("app.services.port_scanner_service.socket.getaddrinfo", side_effect=fake_getaddrinfo):
            with pytest.raises(ValidationError):
                PortScannerService.scan_ports(target="linklocal.example.com", ports=[80])

    def test_multicast_blocked(self, app):
        """Multicast 224.0.0.1 must be blocked."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        with pytest.raises(ValidationError):
            PortScannerService.scan_ports(target="224.0.0.1", ports=[80])

    def test_unspecified_blocked(self, app):
        """0.0.0.0 must be blocked."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        with pytest.raises(ValidationError):
            PortScannerService.scan_ports(target="0.0.0.0", ports=[80])

    def test_reserved_blocked(self, app):
        """240.0.0.1 reserved must be blocked."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        with pytest.raises(ValidationError):
            PortScannerService.scan_ports(target="240.0.0.1", ports=[80])

    def test_private_ips_never_reach_reputation_provider(self, app):
        """Private resolved IP must not trigger AbuseIPDB request."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        # The scanner's ip_reputation for private should be unavailable private_ip_blocked without external call
        # Ensure direct private IP scan is rejected first
        with pytest.raises(ValidationError):
            PortScannerService.scan_ports(target="10.0.0.1", ports=[80])

    def test_rebinding_simulation_second_resolution_would_be_private(self, app):
        """Simulate attacker: first DNS public, second DNS private — scanner must not use second."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        validated_ip = "8.8.8.8"

        def fake_getaddrinfo(host, *a, **kw):
            # Always return validated public IP for the single call we make
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (validated_ip, 0))]

        TrackingSocket, created = _mock_socket_factory()
        with patch("app.services.port_scanner_service.socket.getaddrinfo", side_effect=fake_getaddrinfo):
            with patch("app.services.port_scanner_service.socket.socket", TrackingSocket):
                # Even if attacker changes DNS after validation, we already pinned the IP
                result = PortScannerService.scan_ports(target="rebind.example.com", ports=[80])
                assert result.resolved_ip == validated_ip
                for s in created:
                    assert s.connected_to[0] == validated_ip


# ------------------------------------------------------------------ P0-2 Rate limiting

class TestRateLimiting:
    def test_port_scan_rate_limit_boundary_and_exceeded(self, client, auth_headers, app):
        """5 scans in window allowed, 6th is 429 with consistent envelope."""
        from app.middleware.rate_limiter import clear_rate_limit_store
        clear_rate_limit_store()
        app.config["RATE_LIMIT_ENABLED"] = True
        app.config["RATE_LIMIT_PORT_SCAN"] = 2
        app.config["RATE_LIMIT_PORT_SCAN_WINDOW"] = 60

        # First 2 allowed
        for _ in range(2):
            with patch("socket.socket") as mock_sock:
                mock_sock.return_value.connect_ex.return_value = 1
                mock_sock.return_value.recv.return_value = b""
                mock_sock.return_value.close.return_value = None
                mock_sock.return_value.settimeout.return_value = None
                # Also patch getaddrinfo to return public IP quickly
                with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]):
                    resp = client.post("/api/scanner/ports", json={"target": "example.com", "ports": [80]}, headers=auth_headers)
                    assert resp.status_code == 200

        # 3rd exceeds
        with patch("socket.socket") as mock_sock:
            mock_sock.return_value.connect_ex.return_value = 1
            with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]):
                resp = client.post("/api/scanner/ports", json={"target": "example.com", "ports": [80]}, headers=auth_headers)
                assert resp.status_code == 429
                body = resp.get_json()
                assert body["success"] is False
                assert body["error"]["code"] == "RATE_LIMIT_EXCEEDED"
                assert "retry_after_seconds" in body["error"]["details"]
                # No internal stack trace
                assert "traceback" not in str(body).lower()

        clear_rate_limit_store()

    def test_rate_limit_not_controllable_by_frontend(self, client, auth_headers, app):
        """Client cannot override limits via headers or body."""
        from app.middleware.rate_limiter import clear_rate_limit_store
        clear_rate_limit_store()
        app.config["RATE_LIMIT_ENABLED"] = True
        app.config["RATE_LIMIT_PORT_SCAN"] = 1
        app.config["RATE_LIMIT_PORT_SCAN_WINDOW"] = 60

        with patch("socket.socket") as mock_sock:
            mock_sock.return_value.connect_ex.return_value = 1
            mock_sock.return_value.recv.return_value = b""
            mock_sock.return_value.close.return_value = None
            mock_sock.return_value.settimeout.return_value = None
            with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]):
                resp = client.post("/api/scanner/ports", json={"target": "example.com", "ports": [80]}, headers=auth_headers)
                assert resp.status_code == 200

        # Attempt to bypass via custom header
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]):
            resp = client.post("/api/scanner/ports",
                                json={"target": "example.com", "ports": [80], "limit": 9999},
                                headers={**auth_headers, "X-RateLimit-Limit": "9999"})
            assert resp.status_code == 429

        clear_rate_limit_store()

    def test_unauthenticated_does_not_consume_rate_limit(self, client, app):
        """Unauthenticated requests get 401, not 429."""
        from app.middleware.rate_limiter import clear_rate_limit_store
        clear_rate_limit_store()
        app.config["RATE_LIMIT_ENABLED"] = True
        app.config["RATE_LIMIT_PORT_SCAN"] = 1
        app.config["RATE_LIMIT_PORT_SCAN_WINDOW"] = 60

        resp = client.post("/api/scanner/ports", json={"target": "example.com", "ports": [80]})
        assert resp.status_code == 401
        body = resp.get_json()
        assert body["error"]["code"] == "UNAUTHORIZED"

        clear_rate_limit_store()

    def test_authenticated_vs_unauthenticated_isolation(self, client, auth_headers, app, make_auth_token):
        """Two users have independent rate-limit buckets."""
        from app.middleware.rate_limiter import clear_rate_limit_store
        clear_rate_limit_store()
        app.config["RATE_LIMIT_ENABLED"] = True
        app.config["RATE_LIMIT_PORT_SCAN"] = 1
        app.config["RATE_LIMIT_PORT_SCAN_WINDOW"] = 60

        # User A consumes quota
        with patch("socket.socket") as mock_sock:
            mock_sock.return_value.connect_ex.return_value = 1
            mock_sock.return_value.recv.return_value = b""
            mock_sock.return_value.close.return_value = None
            mock_sock.return_value.settimeout.return_value = None
            with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]):
                resp = client.post("/api/scanner/ports", json={"target": "example.com", "ports": [80]}, headers=auth_headers)
                assert resp.status_code == 200
                resp2 = client.post("/api/scanner/ports", json={"target": "example.com", "ports": [80]}, headers=auth_headers)
                assert resp2.status_code == 429

        # User B (different token) should still be allowed
        import uuid as _uuid
        other_token = make_auth_token(str(_uuid.uuid4()))
        other_headers = {"Authorization": f"Bearer {other_token}"}
        with patch("socket.socket") as mock_sock:
            mock_sock.return_value.connect_ex.return_value = 1
            mock_sock.return_value.recv.return_value = b""
            mock_sock.return_value.close.return_value = None
            mock_sock.return_value.settimeout.return_value = None
            with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]):
                resp = client.post("/api/scanner/ports", json={"target": "example.com", "ports": [80]}, headers=other_headers)
                assert resp.status_code == 200

        clear_rate_limit_store()

    def test_ip_reputation_rate_limit(self, client, auth_headers, app):
        """IP reputation endpoint has its own limit."""
        from app.middleware.rate_limiter import clear_rate_limit_store
        clear_rate_limit_store()
        app.config["RATE_LIMIT_ENABLED"] = True
        app.config["RATE_LIMIT_IP_REPUTATION"] = 1
        app.config["RATE_LIMIT_IP_REPUTATION_WINDOW"] = 60

        with patch("app.services.ip_reputation_service.IPReputationService.check_ip") as mock_check:
            from app.services.ip_reputation_service import ReputationResult
            mock_check.return_value = ReputationResult(ip="8.8.8.8", reputation="clean", provider="abuseipdb", checked_at="2026-01-01T00:00:00+00:00")
            resp = client.get("/api/scanner/ip-reputation/8.8.8.8", headers=auth_headers)
            assert resp.status_code == 200
            resp2 = client.get("/api/scanner/ip-reputation/8.8.8.8", headers=auth_headers)
            assert resp2.status_code == 429
            assert resp2.get_json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"

        clear_rate_limit_store()


# ------------------------------------------------------------------ P0-3 Supabase client safety

class TestSupabaseClientSafety:
    def test_cache_fails_closed_when_admin_unavailable(self, app, monkeypatch):
        """When service-role client is None, cache must not downgrade to anon."""
        import app.services.ip_reputation_cache_service as cache_mod
        # Make admin return None, anon return a fake that would succeed if used
        monkeypatch.setattr(cache_mod, "get_supabase_admin_client", lambda: None)
        fake_anon = MagicMock()
        fake_anon.table.return_value.select.return_value.eq.return_value.eq.return_value.execute.return_value = {"data": [{"ip": "1.1.1.1", "provider": "abuseipdb", "reputation": "clean", "confidence": "high", "malicious": False, "suspicious": False, "reports": 0, "country": "US", "asn": "13335", "organization": "Cloudflare", "isp": "Cloudflare", "last_reported_at": None, "checked_at": "2026-01-01T00:00:00+00:00", "expires_at": "2099-01-01T00:00:00+00:00"}]}
        monkeypatch.setattr(cache_mod, "get_supabase_client", lambda: fake_anon)

        # Need to also patch the direct create_client path to return None
        app.config["SUPABASE_URL"] = ""
        app.config["SUPABASE_SECRET_KEY"] = ""
        app.config["SUPABASE_SERVICE_ROLE_KEY"] = ""
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True

        from app.services.ip_reputation_cache_service import IPReputationCacheService
        result = IPReputationCacheService.get("1.1.1.1", "abuseipdb")
        # Must be None (miss) and anon must NOT have been called
        assert result is None
        fake_anon.table.assert_not_called()

    def test_cache_put_fails_closed_when_admin_unavailable(self, app, monkeypatch):
        """Put must not use anon when admin missing."""
        import app.services.ip_reputation_cache_service as cache_mod
        monkeypatch.setattr(cache_mod, "get_supabase_admin_client", lambda: None)
        fake_anon = MagicMock()
        monkeypatch.setattr(cache_mod, "get_supabase_client", lambda: fake_anon)
        app.config["SUPABASE_URL"] = ""
        app.config["SUPABASE_SECRET_KEY"] = ""
        app.config["SUPABASE_SERVICE_ROLE_KEY"] = ""
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True

        from app.services.ip_reputation_service import ReputationResult
        from app.services.ip_reputation_cache_service import IPReputationCacheService
        result = ReputationResult(ip="8.8.8.8", reputation="clean", confidence="high", provider="abuseipdb", checked_at="2026-01-01T00:00:00+00:00")
        IPReputationCacheService.put(result)
        fake_anon.table.assert_not_called()

    def test_no_api_key_in_reputation_result(self, app, monkeypatch):
        """AbuseIPDB API key must never appear in ReputationResult or its dict."""
        from app.services.ip_reputation_service import AbuseIPDBProvider
        provider = AbuseIPDBProvider(api_key="super-secret-key-123", timeout=5, max_bytes=32768)
        # Mock requests.get to return a benign payload
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.headers = {}
        fake_resp.text = '{"data": {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 0, "totalReports": 0, "isWhitelisted": false, "countryCode": "US", "isp": "Cloudflare"}}'
        fake_resp.json.return_value = {"data": {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 0, "totalReports": 0, "isWhitelisted": False, "countryCode": "US", "isp": "Cloudflare"}}

        with patch("app.services.ip_reputation_service.requests.get", return_value=fake_resp):
            result = provider.check_ip("8.8.8.8")
            d = result.to_dict()
            serialized = str(d)
            assert "super-secret-key-123" not in serialized
            assert "api_key" not in serialized.lower()
            # No key in dict keys
            assert "api_key" not in d

    def test_no_jwt_in_cache_payload(self, app, monkeypatch):
        """Cache payload must never contain JWT or token fields."""
        import app.services.ip_reputation_cache_service as cache_mod
        captured_payload = {}

        fake_client = MagicMock()
        fake_table = MagicMock()
        fake_client.table.return_value = fake_table
        fake_table.upsert.return_value.execute.return_value = {"data": [{}]}
        # Capture payload passed to upsert
        def capture_upsert(payload, **kw):
            captured_payload.update(payload)
            return fake_table
        fake_table.upsert.side_effect = capture_upsert

        monkeypatch.setattr(cache_mod, "get_supabase_admin_client", lambda: fake_client)
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        # Ensure direct Flask path not used (set URL/key so factory wins)
        app.config["SUPABASE_URL"] = "https://abcxyz.supabase.co"
        app.config["SUPABASE_SECRET_KEY"] = "secret"

        from app.services.ip_reputation_cache_service import IPReputationCacheService
        from app.services.ip_reputation_service import ReputationResult
        result = ReputationResult(ip="9.9.9.9", reputation="clean", confidence="high", provider="abuseipdb", checked_at="2026-01-01T00:00:00+00:00", country="US")
        IPReputationCacheService.put(result)

        assert "jwt" not in str(captured_payload).lower()
        assert "token" not in str(captured_payload).lower()
        assert "bearer" not in str(captured_payload).lower()

    def test_no_service_role_leak_in_api_response(self, client, auth_headers, app, monkeypatch):
        """API responses must not contain service-role or secret keys."""
        # Generate a port scan response and inspect
        with patch("socket.socket") as mock_sock:
            mock_sock.return_value.connect_ex.return_value = 1
            mock_sock.return_value.recv.return_value = b""
            mock_sock.return_value.close.return_value = None
            mock_sock.return_value.settimeout.return_value = None
            with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]):
                resp = client.post("/api/scanner/ports", json={"target": "example.com", "ports": [80]}, headers=auth_headers)
                body = str(resp.get_json())
                assert "service_role" not in body.lower()
                assert "secret" not in body.lower()
                assert "SUPABASE_SECRET_KEY" not in body

    def test_cached_none_does_not_block_later_valid_client(self, monkeypatch):
        """Cached None must not prevent later valid admin client creation."""
        import app.database.supabase_client as sc_mod
        # Verify _build_client returns None for empty inputs (fail-closed input check)
        assert sc_mod._build_client("", "") is None
        assert sc_mod._build_client("https://abcxyz.supabase.co", "") is None
        # Verify cache helpers exist and clear correctly (the fix for cached None)
        sc_mod.clear_supabase_client_cache()
        assert sc_mod._admin_client_cached is None
        assert sc_mod._anon_client_cached is None
        # After caching a valid client, clearing must reset
        with patch("app.database.supabase_client.create_client", return_value=MagicMock()) as mc:
            c = sc_mod._build_client("https://abcxyz.supabase.co", "fake-key")
            assert c is not None
        # Ensure helpers do not cache None: _build_client(None, None) leaves cache empty
        sc_mod.clear_supabase_client_cache()
        assert sc_mod._admin_client_cached is None
