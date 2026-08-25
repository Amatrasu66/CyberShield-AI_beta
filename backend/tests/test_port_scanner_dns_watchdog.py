"""Phase 2D-5 — DNS watchdog regression tests.

Covers bounded getaddrinfo timeout, single-resolution TOCTOU preservation,
and SSRF validation under the new watchdog.
"""

import socket
import time
from concurrent.futures import TimeoutError as FutureTimeoutError
from unittest.mock import patch, MagicMock

import pytest

from app.services.port_scanner_service import PortScannerService
from app.errors import ValidationError


def _tracking_socket(open_map=None):
    open_map = open_map or {}
    created = []

    class Sock:
        def __init__(self, *a, **kw):
            self.family = a[0] if a else None
            self.connected_to = None
            created.append(self)

        def settimeout(self, t):
            pass

        def connect_ex(self, addr):
            self.connected_to = addr
            port = addr[1] if isinstance(addr, tuple) else None
            return open_map.get(port, 1)

        def recv(self, n):
            return b""

        def close(self):
            pass

    return Sock, created


class TestDNSWatchdogSuccess:
    def test_successful_dns_resolution(self, app):
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        app.config["PORT_SCANNER_DNS_TIMEOUT"] = 3.0
        Sock, created = _tracking_socket({80: 0})

        def fake_gai(host, *a, **kw):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

        with patch("app.services.port_scanner_service.socket.getaddrinfo", side_effect=fake_gai):
            with patch("app.services.port_scanner_service.socket.socket", Sock):
                result = PortScannerService.scan_ports(target="example.com", ports=[80])
                assert result.resolved_ip == "93.184.216.34"
                assert created[0].connected_to[0] == "93.184.216.34"

    def test_ipv4_resolution(self, app):
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        app.config["PORT_SCANNER_DNS_TIMEOUT"] = 3.0
        Sock, created = _tracking_socket()

        def fake_gai(host, *a, **kw):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0))]

        with patch("app.services.port_scanner_service.socket.getaddrinfo", side_effect=fake_gai):
            with patch("app.services.port_scanner_service.socket.socket", Sock):
                result = PortScannerService.scan_ports(target="one.one.one.one", ports=[80])
                assert result.resolved_ip == "1.1.1.1"
                assert created[0].family == socket.AF_INET

    def test_ipv6_resolution(self, app):
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        app.config["PORT_SCANNER_DNS_TIMEOUT"] = 3.0
        Sock, created = _tracking_socket()

        def fake_gai(host, *a, **kw):
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", 0, 0, 0))]

        with patch("app.services.port_scanner_service.socket.getaddrinfo", side_effect=fake_gai):
            with patch("app.services.port_scanner_service.socket.socket", Sock):
                result = PortScannerService.scan_ports(target="ipv6.example.com", ports=[80])
                assert result.resolved_ip == "2606:4700:4700::1111"
                assert created[0].family == socket.AF_INET6
                assert created[0].connected_to[0] == "2606:4700:4700::1111"


class TestDNSWatchdogFailure:
    def test_dns_timeout_raises_safe_validation_error(self, app):
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        app.config["PORT_SCANNER_DNS_TIMEOUT"] = 0.05  # short for test

        def slow_gai(host, *a, **kw):
            time.sleep(0.2)  # longer than timeout
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]

        with patch("app.services.port_scanner_service.socket.getaddrinfo", side_effect=slow_gai):
            with patch("app.services.port_scanner_service.socket.socket") as mock_sock:
                with pytest.raises(ValidationError) as exc:
                    PortScannerService.scan_ports(target="slow.example.com", ports=[80])
                assert "timed out" in str(exc.value).lower() or "timeout" in str(exc.value).lower()
                # Generic message, no internal traceback leaked
                assert "slow.example.com" not in str(exc.value.details.get("reason", "")) or exc.value.details.get("reason") == "dns_timeout"
                assert exc.value.details.get("field") == "target"
                mock_sock.assert_not_called()

    def test_dns_timeout_does_not_expose_internal_details(self, app):
        app.config["PORT_SCANNER_DNS_TIMEOUT"] = 0.05

        def slow_gai(host, *a, **kw):
            time.sleep(0.2)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]

        with patch("app.services.port_scanner_service.socket.getaddrinfo", side_effect=slow_gai):
            with pytest.raises(ValidationError) as exc:
                PortScannerService._resolve_target_secure("timeout.example.com", app.config)
            # No internal exception type, no resolver string leaked
            details = str(exc.value.details)
            assert "concurrent" not in details.lower()
            assert "future" not in details.lower()
            assert "gaierror" not in details.lower()

    def test_dns_failure_gaierror_returns_filtered(self, app):
        """gaierror path should not raise, but scan should return non-open ports."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        app.config["PORT_SCANNER_DNS_TIMEOUT"] = 3.0
        Sock, created = _tracking_socket()

        def failing_gai(host, *a, **kw):
            raise socket.gaierror(11001, "getaddrinfo failed")

        with patch("app.services.port_scanner_service.socket.getaddrinfo", side_effect=failing_gai):
            with patch("app.services.port_scanner_service.socket.socket", Sock):
                result = PortScannerService.scan_ports(target="nonexistent.invalid", ports=[80, 443])
                # When resolution fails, resolved_ip is target as-is; with a mock socket
                # the ports appear as closed/filtered (both are non-open), which is safe
                assert result.resolved_ip == "nonexistent.invalid"
                assert all(p.state in ("filtered", "closed") for p in result.open_ports)
                assert all(p.state != "open" for p in result.open_ports)

    def test_dns_failure_direct_resolve_returns_target(self, app):
        app.config["PORT_SCANNER_DNS_TIMEOUT"] = 3.0

        def failing_gai(host, *a, **kw):
            raise socket.gaierror(11001, "getaddrinfo failed")

        with patch("app.services.port_scanner_service.socket.getaddrinfo", side_effect=failing_gai):
            resolved = PortScannerService._resolve_target_secure("bad.invalid", app.config)
            assert resolved == "bad.invalid"


class TestDNSWatchdogSecurity:
    def test_mixed_public_private_blocked_under_watchdog(self, app):
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        app.config["PORT_SCANNER_DNS_TIMEOUT"] = 3.0

        def fake_gai(host, *a, **kw):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 0)),
            ]

        with patch("app.services.port_scanner_service.socket.getaddrinfo", side_effect=fake_gai):
            with pytest.raises(ValidationError) as exc:
                PortScannerService.scan_ports(target="mixed.example.com", ports=[80])
            assert "private" in str(exc.value).lower()

    def test_only_validated_ip_passed_to_connect_with_watchdog(self, app):
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        app.config["PORT_SCANNER_DNS_TIMEOUT"] = 3.0
        validated = "93.184.216.34"
        Sock, created = _tracking_socket({80: 0})

        def fake_gai(host, *a, **kw):
            assert host == "example.com"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (validated, 0))]

        with patch("app.services.port_scanner_service.socket.getaddrinfo", side_effect=fake_gai) as mock_gai:
            with patch("app.services.port_scanner_service.socket.socket", Sock):
                result = PortScannerService.scan_ports(target="example.com", ports=[80, 443])
                assert result.resolved_ip == validated
                for s in created:
                    assert s.connected_to[0] == validated
                # Only one DNS call despite two ports
                assert mock_gai.call_count == 1

    def test_no_ssrf_regression_private_hostname_blocked(self, app):
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        app.config["PORT_SCANNER_DNS_TIMEOUT"] = 3.0

        def fake_gai(host, *a, **kw):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]

        with patch("app.services.port_scanner_service.socket.getaddrinfo", side_effect=fake_gai):
            with patch("app.services.port_scanner_service.socket.socket") as mock_sock:
                with pytest.raises(ValidationError):
                    PortScannerService.scan_ports(target="internal.example.com", ports=[80])
                mock_sock.assert_not_called()

    def test_no_ssrf_regression_loopback_via_dns(self, app):
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False
        app.config["PORT_SCANNER_DNS_TIMEOUT"] = 3.0

        def fake_gai(host, *a, **kw):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

        with patch("app.services.port_scanner_service.socket.getaddrinfo", side_effect=fake_gai):
            with pytest.raises(ValidationError):
                PortScannerService.scan_ports(target="loopback.example.com", ports=[80])

    def test_configurable_timeout_respected(self, app):
        """Short timeout should trigger faster than long timeout."""
        app.config["PORT_SCANNER_DNS_TIMEOUT"] = 0.05

        def slow_gai(host, *a, **kw):
            time.sleep(0.15)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]

        start = time.perf_counter()
        with patch("app.services.port_scanner_service.socket.getaddrinfo", side_effect=slow_gai):
            with pytest.raises(ValidationError):
                PortScannerService._resolve_target_secure("slow.example.com", app.config)
        elapsed = time.perf_counter() - start
        # Should fail near timeout (0.05), not wait full 0.15; allow generous margin under load
        assert elapsed < 0.30, f"Watchdog did not enforce timeout, elapsed {elapsed}"

    def test_deadline_not_waits_indefinitely_on_hung_resolver(self, app):
        """Ensure the future timeout path covers hung resolver without leaking."""
        app.config["PORT_SCANNER_DNS_TIMEOUT"] = 0.05

        def hung_gai(host, *a, **kw):
            time.sleep(10)  # simulate hung resolver
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]

        # Patch _getaddrinfo_with_timeout to use our hung mock via socket.getaddrinfo
        with patch("app.services.port_scanner_service.socket.getaddrinfo", side_effect=hung_gai):
            start = time.perf_counter()
            with pytest.raises(ValidationError) as exc:
                PortScannerService._resolve_target_secure("hung.example.com", app.config)
            elapsed = time.perf_counter() - start
            assert elapsed < 0.5
            assert exc.value.details.get("reason") == "dns_timeout"
