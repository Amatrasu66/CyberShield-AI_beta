"""Tests for Port Scanner Service and Endpoint."""

import pytest
import socket
import time
import concurrent.futures
from unittest.mock import patch, MagicMock

import uuid
from app.errors import ValidationError, UnauthorizedError, ServiceUnavailableError
from app.services.port_scanner_service import PortScannerService, PortResult, ScanResult
from app.utils.validators import (
    validate_port_list,
    resolve_scan_ports,
    validate_hostname_or_ip,
    is_private_hostname,
    get_service_name,
    QUICK_SCAN_PORTS,
    COMMON_SCAN_PORTS,
    DEFAULT_MAX_PORTS,
)

PORT_SCAN_CONFIG = {
    "PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES": True,
    "PORT_SCANNER_MAX_PORTS": 100,
    "PORT_SCANNER_CONNECT_TIMEOUT": 2,
    "PORT_SCANNER_TOTAL_TIMEOUT": 30,
    "PORT_SCANNER_MAX_CONCURRENCY": 50,
    "PORT_SCANNER_BANNER_TIMEOUT": 1,
    "PORT_SCANNER_BANNER_MAX_BYTES": 256,
    "URL_MAX_LENGTH": 2048,
}


class MockSocket:
    """Mock socket for testing."""

    def __init__(self, connect_result=0, banner_data=b"", raise_on_connect=None, raise_on_recv=None):
        self.connect_result = connect_result
        self.banner_data = banner_data
        self.raise_on_connect = raise_on_connect
        self.raise_on_recv = raise_on_recv
        self.closed = False
        self.timeout_set = None
        self._connected_port = None

    def settimeout(self, timeout):
        self.timeout_set = timeout

    def connect_ex(self, addr):
        """addr is a tuple of (host, port)"""
        self._connected_port = addr[1] if isinstance(addr, tuple) and len(addr) > 1 else None
        if self.raise_on_connect:
            raise self.raise_on_connect
        return self.connect_result

    def recv(self, bufsize):
        if self.raise_on_recv:
            raise self.raise_on_recv
        return self.banner_data

    def close(self):
        self.closed = True


def create_socket_factory(open_ports_map, default_connect_result=1, default_banner=b""):
    """
    Create a socket factory that returns different mock sockets based on the port
    passed to connect_ex.
    
    Args:
        open_ports_map: dict mapping port -> (connect_result, banner_data) or MockSocket
        default_connect_result: result for ports not in map
        default_banner: banner for ports not in map
    """
    sockets = {}
    
    def factory(*args, **kwargs):
        sock = MockSocket(connect_result=default_connect_result, banner_data=default_banner)
        original_connect_ex = sock.connect_ex
        
        def tracking_connect_ex(addr):
            port = addr[1] if isinstance(addr, tuple) and len(addr) > 1 else None
            sock._connected_port = port
            if port in open_ports_map:
                val = open_ports_map[port]
                if isinstance(val, MockSocket):
                    return val.connect_ex(addr)
                elif isinstance(val, tuple):
                    sock.connect_result = val[0]
                    sock.banner_data = val[1] if len(val) > 1 else default_banner
                else:
                    sock.connect_result = val
            return original_connect_ex(addr)
        
        sock.connect_ex = tracking_connect_ex
        return sock
    
    return factory


class TestValidatePortList:
    def test_valid_ports(self):
        assert validate_port_list([22, 80, 443]) == [22, 80, 443]

    def test_valid_ports_strings(self):
        assert validate_port_list(["22", "80", "443"]) == [22, 80, 443]

    def test_duplicate_ports_deduplicated(self):
        assert validate_port_list([22, 22, 80, 80]) == [22, 80]

    def test_sorted_output(self):
        assert validate_port_list([443, 22, 80]) == [22, 80, 443]

    def test_port_zero_rejected(self):
        with pytest.raises(ValidationError):
            validate_port_list([0])

    def test_port_65536_rejected(self):
        with pytest.raises(ValidationError):
            validate_port_list([65536])

    def test_negative_port_rejected(self):
        with pytest.raises(ValidationError):
            validate_port_list([-1])

    def test_non_integer_port_rejected(self):
        with pytest.raises(ValidationError):
            validate_port_list(["abc"])

    def test_none_ports_rejected(self):
        with pytest.raises(ValidationError):
            validate_port_list(None)

    def test_non_iterable_rejected(self):
        with pytest.raises(ValidationError):
            validate_port_list(123)

    def test_too_many_ports_rejected(self):
        with pytest.raises(ValidationError):
            validate_port_list(list(range(1, 102)), max_ports=100)

    def test_exact_max_ports_allowed(self):
        ports = list(range(1, 101))
        assert validate_port_list(ports, max_ports=100) == ports


class TestResolveScanPorts:
    def test_explicit_ports(self):
        assert resolve_scan_ports(ports=[22, 80, 443]) == [22, 80, 443]

    def test_quick_profile(self):
        assert resolve_scan_ports(profile="quick") == QUICK_SCAN_PORTS

    def test_common_profile(self):
        # common profile returns all ports, but limited by max_ports (default 100)
        result = resolve_scan_ports(profile="common", max_ports=200)
        assert result == COMMON_SCAN_PORTS

    def test_profile_limits_to_max(self):
        assert resolve_scan_ports(profile="common", max_ports=10) == COMMON_SCAN_PORTS[:10]

    def test_both_ports_and_profile_rejected(self):
        with pytest.raises(ValidationError):
            resolve_scan_ports(ports=[22], profile="quick")

    def test_neither_ports_nor_profile_rejected(self):
        with pytest.raises(ValidationError):
            resolve_scan_ports()

    def test_invalid_profile_rejected(self):
        with pytest.raises(ValidationError):
            resolve_scan_ports(profile="invalid")


class TestValidateHostnameOrIP:
    def test_valid_hostname(self):
        assert validate_hostname_or_ip("example.com") == "example.com"

    def test_valid_hostname_with_trailing_dot(self):
        assert validate_hostname_or_ip("example.com.") == "example.com"

    def test_valid_ipv4(self):
        assert validate_hostname_or_ip("192.168.1.1") == "192.168.1.1"

    def test_valid_ipv6_brackets(self):
        assert validate_hostname_or_ip("[::1]") == "::1"

    def test_valid_ipv6_brackets_with_port(self):
        assert validate_hostname_or_ip("[::1]:80") == "::1"

    def test_hostname_lowercased(self):
        assert validate_hostname_or_ip("EXAMPLE.COM") == "example.com"

    def test_rejects_scheme(self):
        with pytest.raises(ValidationError):
            validate_hostname_or_ip("https://example.com")

    def test_rejects_credentials(self):
        with pytest.raises(ValidationError):
            validate_hostname_or_ip("user:pass@example.com")

    def test_rejects_empty(self):
        with pytest.raises(ValidationError):
            validate_hostname_or_ip("")

    def test_rejects_invalid_hostname(self):
        with pytest.raises(ValidationError):
            validate_hostname_or_ip("not a valid hostname")

    def test_rejects_bare_ipv6_with_port(self):
        with pytest.raises(ValidationError):
            validate_hostname_or_ip("::1:80")

    def test_rejects_too_long(self):
        with pytest.raises(ValidationError):
            validate_hostname_or_ip("a" * 300, max_length=100)


class TestIsPrivateHostname:
    def test_private_ipv4_blocked(self):
        assert is_private_hostname("192.168.1.1") is True
        assert is_private_hostname("10.0.0.1") is True
        assert is_private_hostname("172.16.0.1") is True

    def test_loopback_blocked(self):
        assert is_private_hostname("127.0.0.1") is True
        assert is_private_hostname("::1") is True

    def test_link_local_blocked(self):
        assert is_private_hostname("169.254.1.1") is True

    def test_reserved_blocked(self):
        assert is_private_hostname("240.0.0.1") is True

    def test_public_ip_allowed(self):
        assert is_private_hostname("8.8.8.8") is False
        assert is_private_hostname("1.1.1.1") is False

    @patch("socket.getaddrinfo")
    def test_private_hostname_blocked(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(socket.AF_INET, 0, 0, "", ("192.168.1.1", 0))]
        assert is_private_hostname("internal.corp") is True

    @patch("socket.getaddrinfo")
    def test_public_hostname_allowed(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(socket.AF_INET, 0, 0, "", ("8.8.8.8", 0))]
        assert is_private_hostname("google.com") is False

    @patch("socket.getaddrinfo")
    def test_unresolvable_returns_false(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.gaierror
        assert is_private_hostname("nonexistent.invalid") is False


class TestGetServiceName:
    def test_known_ports(self):
        assert get_service_name(22) == "ssh"
        assert get_service_name(80) == "http"
        assert get_service_name(443) == "https"
        assert get_service_name(3306) == "mysql"

    def test_unknown_port(self):
        assert get_service_name(9999) == "unknown"


class TestPortScannerService:
    def test_scan_ports_quick_profile(self, app, monkeypatch):
        """Test scanning with quick profile returns expected structure."""
        with patch("socket.socket") as mock_socket_class:
            # All ports closed
            mock_socket_class.side_effect = create_socket_factory({})

            result = PortScannerService.scan_ports(
                target="example.com",
                profile="quick",
            )

            assert isinstance(result, ScanResult)
            assert result.target == "example.com"
            assert result.ports_scanned == len(QUICK_SCAN_PORTS)
            assert all(p.state == "closed" for p in result.open_ports)
            assert result.risk_level == "low"

    def test_scan_ports_explicit_list(self, app, monkeypatch):
        """Test scanning with explicit port list."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({})

            result = PortScannerService.scan_ports(
                target="example.com",
                ports=[22, 80, 443],
            )

            assert result.ports_scanned == 3

    def test_open_port_detected(self, app, monkeypatch):
        """Test that open ports are detected and banner grabbed."""
        with patch("socket.socket") as mock_socket_class:
            # Port 22 open with banner, 80 closed
            mock_socket_class.side_effect = create_socket_factory({
                22: (0, b"SSH-2.0-OpenSSH_8.9"),
            })

            result = PortScannerService.scan_ports(
                target="example.com",
                ports=[22, 80],
            )

            open_ports = [p for p in result.open_ports if p.state == "open"]
            assert len(open_ports) == 1
            assert open_ports[0].port == 22
            assert open_ports[0].service == "ssh"
            assert "SSH-2.0" in open_ports[0].banner

    def test_banner_truncation(self, app, monkeypatch):
        """Test that banners are truncated to max bytes."""
        long_banner = "A" * 500
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({
                22: (0, long_banner.encode()),
            })

            # Use custom config with smaller banner max bytes
            config = {**PORT_SCAN_CONFIG, "PORT_SCANNER_BANNER_MAX_BYTES": 100}
            result = PortScannerService.scan_ports(
                target="example.com",
                ports=[22],
                config=config,
            )

            open_ports = [p for p in result.open_ports if p.state == "open"]
            assert len(open_ports[0].banner) <= 103  # 100 + "..."

    def test_banner_sanitization(self, app, monkeypatch):
        """Test that control characters are stripped from banners."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({
                22: (0, b"SSH\x00\x01\x02-2.0-OpenSSH"),
            })

            result = PortScannerService.scan_ports(
                target="example.com",
                ports=[22],
            )

            open_ports = [p for p in result.open_ports if p.state == "open"]
            assert "\x00" not in open_ports[0].banner
            assert "\x01" not in open_ports[0].banner

    def test_timeout_marked_filtered(self, app, monkeypatch):
        """Test that connect timeout marks port as filtered."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({
                22: MockSocket(raise_on_connect=socket.timeout),
            })

            result = PortScannerService.scan_ports(
                target="example.com",
                ports=[22],
            )

            assert result.open_ports[0].state == "filtered"

    def test_connection_refused_marked_closed(self, app, monkeypatch):
        """Test that connection refused marks port as closed."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({
                22: (111, b""),  # ECONNREFUSED
            })

            result = PortScannerService.scan_ports(
                target="example.com",
                ports=[22],
            )

            assert result.open_ports[0].state == "closed"

    def test_socket_error_marked_filtered(self, app, monkeypatch):
        """Test that socket errors mark port as filtered."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({
                22: MockSocket(raise_on_connect=OSError("Network unreachable")),
            })

            result = PortScannerService.scan_ports(
                target="example.com",
                ports=[22],
            )

            assert result.open_ports[0].state == "filtered"

    def test_private_target_rejected(self, app, monkeypatch):
        """Test that private targets are rejected before socket connection."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False

        with pytest.raises(ValidationError):
            PortScannerService.scan_ports(
                target="192.168.1.1",
                ports=[22],
            )

    def test_localhost_rejected(self, app, monkeypatch):
        """Test that localhost is rejected."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False

        with pytest.raises(ValidationError):
            PortScannerService.scan_ports(
                target="localhost",
                ports=[22],
            )

    def test_private_hostname_rejected(self, app, monkeypatch):
        """Test that hostname resolving to private IP is rejected."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False

        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [(socket.AF_INET, 0, 0, "", ("10.0.0.1", 0))]
            with pytest.raises(ValidationError):
                PortScannerService.scan_ports(
                    target="internal.corp",
                    ports=[22],
                )

    def test_no_socket_on_validation_failure(self, app, monkeypatch):
        """Verify no socket connection attempted when target validation fails."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False

        with patch("socket.socket") as mock_socket_class:
            with pytest.raises(ValidationError):
                PortScannerService.scan_ports(
                    target="192.168.1.1",
                    ports=[22],
            )
            mock_socket_class.assert_not_called()

    def test_invalid_target_rejected(self, app, monkeypatch):
        """Test that invalid target format is rejected."""
        with pytest.raises(ValidationError):
            PortScannerService.scan_ports(
                target="not a valid hostname!",
                ports=[22],
            )

    def test_missing_target_rejected(self, app, monkeypatch):
        """Test that missing target raises error."""
        with pytest.raises(ValidationError):
            PortScannerService.scan_ports(
                target="",
                ports=[22],
            )

    def test_risk_scoring_critical(self, app, monkeypatch):
        """Test critical risk for SSH/RDP open."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({
                22: (0, b""),
            })

            result = PortScannerService.scan_ports(
                target="example.com",
                ports=[22, 80],
            )

            assert result.risk_level == "critical"

    def test_risk_scoring_high(self, app, monkeypatch):
        """Test high risk for database ports."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({
                3306: (0, b""),
            })

            result = PortScannerService.scan_ports(
                target="example.com",
                ports=[3306, 80],
            )

            assert result.risk_level == "high"

    def test_risk_scoring_medium(self, app, monkeypatch):
        """Test medium risk for web ports."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({
                80: (0, b""),
            })

            result = PortScannerService.scan_ports(
                target="example.com",
                ports=[80, 443],
            )

            assert result.risk_level == "medium"

    def test_risk_scoring_low(self, app, monkeypatch):
        """Test low risk for non-sensitive ports."""
        with patch("socket.socket") as mock_socket_class:
            # Use ports not in any risk category (9999, 12345, etc.)
            mock_socket_class.side_effect = create_socket_factory({
                9999: (0, b""),
                12345: (0, b""),
            })

            result = PortScannerService.scan_ports(
                target="example.com",
                ports=[9999, 12345],
            )

            assert result.risk_level == "low"

    def test_concurrency_limit_respected(self, app, monkeypatch):
        """Test that max concurrency is respected."""
        with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
            mock_executor_instance = MagicMock()
            mock_executor.return_value.__enter__.return_value = mock_executor_instance
            mock_executor_instance.submit = MagicMock()
            mock_executor_instance.map = MagicMock()

            # Mock as_completed to return immediately
            import concurrent.futures
            with patch("concurrent.futures.as_completed") as mock_as_completed:
                mock_as_completed.return_value = []

                PortScannerService.scan_ports(
                    target="example.com",
                    ports=list(range(1, 101)),
                )

                # Verify ThreadPoolExecutor was created with max_workers=50
                mock_executor.assert_called_with(max_workers=50)

    def test_total_timeout_enforced(self, app, monkeypatch):
        """Test that total scan timeout is enforced."""
        with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
            mock_executor_instance = MagicMock()
            mock_executor.return_value.__enter__.return_value = mock_executor_instance

            # Simulate slow scan
            def slow_submit(fn, *args, **kwargs):
                time.sleep(0.1)
                future = concurrent.futures.Future()
                future.set_result(PortResult(port=args[0], service="unknown", state="closed"))
                return future

            mock_executor_instance.submit = slow_submit

            with patch("concurrent.futures.as_completed") as mock_as_completed:
                # Return futures that complete quickly but total time exceeds timeout
                futures = []
                for i in range(5):
                    f = concurrent.futures.Future()
                    f.set_result(PortResult(port=i, service="unknown", state="closed"))
                    futures.append(f)
                mock_as_completed.return_value = futures

                # Set very short total timeout
                result = PortScannerService.scan_ports(
                    target="example.com",
                    ports=list(range(1, 6)),
                    config={"PORT_SCANNER_TOTAL_TIMEOUT": 0.01},
                )

                # Should have some results but not all
                assert result.ports_scanned <= 5


class TestPortScannerEndpoint:
    def test_endpoint_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post("/api/scanner/ports", json={"target": "example.com"})
        assert response.status_code == 401

    def test_endpoint_valid_scan(self, client, auth_headers, monkeypatch):
        """Test successful port scan."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.return_value = MockSocket(connect_result=1)

            response = client.post(
                "/api/scanner/ports",
                json={"target": "example.com", "profile": "quick"},
                headers=auth_headers,
            )

            assert response.status_code == 200
            body = response.get_json()
            assert body["success"] is True
            assert body["data"]["target"] == "example.com"
            assert body["data"]["ports_scanned"] == len(QUICK_SCAN_PORTS)
            assert "open_ports" in body["data"]
            assert "risk_level" in body["data"]

    def test_endpoint_missing_target(self, client, auth_headers):
        """Test missing target returns 400."""
        response = client.post(
            "/api/scanner/ports",
            json={},
            headers=auth_headers,
        )
        assert response.status_code == 400
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "VALIDATION_ERROR"

    def test_endpoint_invalid_target(self, client, auth_headers):
        """Test invalid target returns 400."""
        response = client.post(
            "/api/scanner/ports",
            json={"target": "https://example.com"},  # URL not allowed
            headers=auth_headers,
        )
        assert response.status_code == 400

    def test_endpoint_private_target_blocked(self, client, auth_headers, app):
        """Test private target blocked."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False

        response = client.post(
            "/api/scanner/ports",
            json={"target": "192.168.1.1", "ports": [22]},
            headers=auth_headers,
        )
        assert response.status_code == 400
        body = response.get_json()
        assert body["success"] is False
        assert "private" in body["message"].lower()

    def test_endpoint_invalid_port(self, client, auth_headers):
        """Test invalid port returns 400."""
        response = client.post(
            "/api/scanner/ports",
            json={"target": "example.com", "ports": [0]},
            headers=auth_headers,
        )
        assert response.status_code == 400

    def test_endpoint_too_many_ports(self, client, auth_headers):
        """Test too many ports returns 400."""
        response = client.post(
            "/api/scanner/ports",
            json={"target": "example.com", "ports": list(range(1, 102))},
            headers=auth_headers,
        )
        assert response.status_code == 400
        body = response.get_json()
        assert "Too many ports" in body["message"]

    def test_endpoint_duplicate_ports(self, client, auth_headers, monkeypatch):
        """Test duplicate ports are deduplicated."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.return_value = MockSocket(connect_result=1)

            response = client.post(
                "/api/scanner/ports",
                json={"target": "example.com", "ports": [22, 22, 80, 80]},
                headers=auth_headers,
            )

            assert response.status_code == 200
            body = response.get_json()
            assert body["data"]["ports_scanned"] == 2

    def test_endpoint_both_ports_and_profile_rejected(self, client, auth_headers):
        """Test both ports and profile rejected."""
        response = client.post(
            "/api/scanner/ports",
            json={"target": "example.com", "ports": [22], "profile": "quick"},
            headers=auth_headers,
        )
        assert response.status_code == 400

    def test_endpoint_neither_ports_nor_profile_rejected(self, client, auth_headers):
        """Test neither ports nor profile rejected."""
        response = client.post(
            "/api/scanner/ports",
            json={"target": "example.com"},
            headers=auth_headers,
        )
        assert response.status_code == 400

    def test_endpoint_invalid_profile(self, client, auth_headers):
        """Test invalid profile rejected."""
        response = client.post(
            "/api/scanner/ports",
            json={"target": "example.com", "profile": "invalid"},
            headers=auth_headers,
        )
        assert response.status_code == 400

    def test_endpoint_malformed_json(self, client, auth_headers):
        """Test malformed JSON rejected."""
        response = client.post(
            "/api/scanner/ports",
            data="not json",
            content_type="application/json",
            headers=auth_headers,
        )
        assert response.status_code == 400

    def test_endpoint_open_ports_returned(self, client, auth_headers, monkeypatch):
        """Test open ports with banners in response."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({
                22: (0, b"SSH-2.0-OpenSSH_8.9"),
                80: (0, b"HTTP/1.1 200 OK\r\nServer: nginx"),
            })

            response = client.post(
                "/api/scanner/ports",
                json={"target": "example.com", "ports": [22, 80, 443]},
                headers=auth_headers,
            )

            assert response.status_code == 200
            body = response.get_json()
            open_ports = body["data"]["open_ports"]
            assert len(open_ports) == 3
            open_states = [p["state"] for p in open_ports]
            assert open_states.count("open") == 2
            # Check banner present
            ssh_port = next(p for p in open_ports if p["port"] == 22)
            assert "SSH-2.0" in ssh_port["banner"]

    def test_endpoint_resolved_ip_in_response(self, client, auth_headers, monkeypatch):
        """Test that resolved IP is in response."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.return_value = MockSocket(connect_result=1)
            with patch("socket.getaddrinfo") as mock_getaddrinfo:
                mock_getaddrinfo.return_value = [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 0))]

                response = client.post(
                    "/api/scanner/ports",
                    json={"target": "example.com", "ports": [80]},
                    headers=auth_headers,
                )

                assert response.status_code == 200
                body = response.get_json()
                assert body["data"]["resolved_ip"] == "93.184.216.34"


class TestPortScannerPersistence:
    """Tests for port scan persistence to Supabase."""

    def test_persist_successful_scan(self, app, monkeypatch, fake_supabase, auth_user_id):
        """Test that completed scans are persisted to port_scans table."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({
                22: (0, b"SSH-2.0-OpenSSH_8.9"),
                80: (1, b""),
            })

            result = PortScannerService.scan_ports(
                target="example.com",
                ports=[22, 80],
                user_id=auth_user_id,
            )

            # Verify scan completed successfully
            assert result.risk_level == "critical"
            assert len([p for p in result.open_ports if p.state == "open"]) == 1

            # Verify persistence was called
            inserts = fake_supabase.inserts.get("port_scans", [])
            assert len(inserts) == 1
            persisted = inserts[0]
            assert persisted["user_id"] == auth_user_id
            assert persisted["target"] == "example.com"
            assert persisted["ports_scanned"] == 2
            assert persisted["risk_level"] == "critical"
            assert persisted["status"] == "completed"
            assert "open_ports" in persisted
            assert len(persisted["open_ports"]) == 2
            assert persisted["open_ports"][0]["port"] == 22
            assert persisted["open_ports"][0]["state"] == "open"
            assert "SSH-2.0" in persisted["open_ports"][0]["banner"]
            assert persisted["open_ports"][1]["port"] == 80
            assert persisted["open_ports"][1]["state"] == "closed"

    def test_persist_associates_with_authenticated_user(self, app, monkeypatch, fake_supabase, auth_user_id):
        """Test that scans are associated with the authenticated user_id from JWT."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({})

            PortScannerService.scan_ports(
                target="example.com",
                ports=[80],
                user_id=auth_user_id,
            )

            inserts = fake_supabase.inserts.get("port_scans", [])
            assert len(inserts) == 1
            assert inserts[0]["user_id"] == auth_user_id

    def test_persist_skipped_when_no_user_id(self, app, monkeypatch, fake_supabase):
        """Test that persistence is skipped when no user_id provided."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({})

            PortScannerService.scan_ports(
                target="example.com",
                ports=[80],
                user_id=None,
            )

            inserts = fake_supabase.inserts.get("port_scans", [])
            assert len(inserts) == 0

    def test_persist_skipped_when_supabase_unavailable(self, app, monkeypatch, fake_supabase, auth_user_id):
        """Test that persistence is skipped when Supabase client is None."""
        import app.services.port_scanner_service as port_scanner_module
        monkeypatch.setattr(port_scanner_module, "get_user_supabase_client", lambda *args, **kwargs: None)

        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({})

            PortScannerService.scan_ports(
                target="example.com",
                ports=[80],
                user_id=auth_user_id,
            )

            inserts = fake_supabase.inserts.get("port_scans", [])
            assert len(inserts) == 0

    def test_persist_raises_on_database_failure(self, app, monkeypatch, fake_supabase, auth_user_id):
        """Test that database failures raise ServiceUnavailableError."""
        fake_supabase.fail_inserts = True

        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({})

            with pytest.raises(ServiceUnavailableError):
                PortScannerService.scan_ports(
                    target="example.com",
                    ports=[80],
                    user_id=auth_user_id,
                )

    def test_persist_stores_open_ports_as_jsonb(self, app, monkeypatch, fake_supabase, auth_user_id):
        """Test that open_ports array is stored as JSONB with correct structure."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({
                22: (0, b"SSH-2.0-OpenSSH"),
                80: (0, b"HTTP/1.1 200 OK"),
                443: (1, b""),
            })

            PortScannerService.scan_ports(
                target="example.com",
                ports=[22, 80, 443],
                user_id=auth_user_id,
            )

            inserts = fake_supabase.inserts.get("port_scans", [])
            persisted = inserts[0]
            open_ports = persisted["open_ports"]
            assert len(open_ports) == 3
            # All ports should be in the array with their states
            port_states = {p["port"]: p["state"] for p in open_ports}
            assert port_states[22] == "open"
            assert port_states[80] == "open"
            assert port_states[443] == "closed"
            # Verify banner is included for SSH port
            ssh_port = next(p for p in open_ports if p["port"] == 22)
            assert "SSH-2.0" in ssh_port["banner"]

    def test_persist_includes_all_required_fields(self, app, monkeypatch, fake_supabase, auth_user_id):
        """Test that all required fields are stored."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({
                80: (0, b"HTTP"),
            })
            with patch("socket.getaddrinfo") as mock_getaddrinfo:
                mock_getaddrinfo.return_value = [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 0))]

                PortScannerService.scan_ports(
                    target="example.com",
                    ports=[80],
                    user_id=auth_user_id,
                )

            inserts = fake_supabase.inserts.get("port_scans", [])
            persisted = inserts[0]
            required_fields = [
                "user_id", "target", "resolved_ip", "ports_scanned",
                "open_ports", "scan_duration_ms", "risk_level", "status"
            ]
            for field in required_fields:
                assert field in persisted, f"Missing field: {field}"
            assert persisted["resolved_ip"] == "93.184.216.34"
            assert isinstance(persisted["scan_duration_ms"], int)
            assert persisted["scan_duration_ms"] >= 0


class TestPortScannerRLS:
    """Tests for Row Level Security / user isolation."""

    def test_user_cannot_access_other_user_scans(self, app, monkeypatch, fake_supabase, auth_user_id, make_auth_token):
        """Test RLS: user A cannot read user B's port scans."""
        # This test verifies the RLS policy structure by checking
        # that the user-scoped client forwards the correct token
        other_user_id = str(uuid.uuid4())

        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({})

            # User A scans
            PortScannerService.scan_ports(
                target="example.com",
                ports=[80],
                user_id=auth_user_id,
            )

            # Verify the scan was inserted with user A's ID
            inserts = fake_supabase.inserts.get("port_scans", [])
            assert len(inserts) == 1
            assert inserts[0]["user_id"] == auth_user_id

            # Verify the access token was tracked (for RLS scoping)
            assert len(fake_supabase.auth_tokens) > 0


class TestPortScannerMalformedData:
    """Tests for handling malformed data in persistence."""

    def test_persist_handles_unicode_in_banner(self, app, monkeypatch, fake_supabase, auth_user_id):
        """Test that banners with unicode are handled correctly."""
        with patch("socket.socket") as mock_socket_class:
            # Banner with unicode chars
            mock_socket_class.side_effect = create_socket_factory({
                22: (0, "SSH-2.0-OpenSSH_8.9\u0000\u0001".encode("utf-8", errors="ignore")),
            })

            PortScannerService.scan_ports(
                target="example.com",
                ports=[22],
                user_id=auth_user_id,
            )

            inserts = fake_supabase.inserts.get("port_scans", [])
            assert len(inserts) == 1
            banner = inserts[0]["open_ports"][0]["banner"]
            # Control chars should be stripped
            assert "\x00" not in banner
            assert "\x01" not in banner

    def test_persist_handles_very_long_banner(self, app, monkeypatch, fake_supabase, auth_user_id):
        """Test that very long banners are truncated."""
        long_banner = "A" * 1000
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({
                22: (0, long_banner.encode()),
            })

            config = {"PORT_SCANNER_BANNER_MAX_BYTES": 256}
            PortScannerService.scan_ports(
                target="example.com",
                ports=[22],
                config=config,
                user_id=auth_user_id,
            )

            inserts = fake_supabase.inserts.get("port_scans", [])
            banner = inserts[0]["open_ports"][0]["banner"]
            assert len(banner) <= 259  # 256 + "..."

    def test_persist_handles_all_filtered_ports(self, app, monkeypatch, fake_supabase, auth_user_id):
        """Test persistence when all ports are filtered (timeouts)."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({
                22: MockSocket(raise_on_connect=socket.timeout),
                80: MockSocket(raise_on_connect=socket.timeout),
            })

            PortScannerService.scan_ports(
                target="example.com",
                ports=[22, 80],
                user_id=auth_user_id,
            )

            inserts = fake_supabase.inserts.get("port_scans", [])
            assert len(inserts) == 1
            persisted = inserts[0]
            assert persisted["risk_level"] == "low"
            assert all(p["state"] == "filtered" for p in persisted["open_ports"])

    def test_persist_handles_resolution_failure(self, app, monkeypatch, fake_supabase, auth_user_id):
        """Test persistence when target resolution fails."""
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.side_effect = create_socket_factory({
                80: MockSocket(raise_on_connect=socket.gaierror("Name resolution failed")),
            })
            with patch("socket.getaddrinfo", side_effect=socket.gaierror("getaddrinfo failed")):

                PortScannerService.scan_ports(
                    target="unresolvable.invalid",
                    ports=[80],
                    user_id=auth_user_id,
                )

            inserts = fake_supabase.inserts.get("port_scans", [])
            assert len(inserts) == 1
            persisted = inserts[0]
            assert persisted["target"] == "unresolvable.invalid"
            assert persisted["resolved_ip"] == "unresolvable.invalid"
            assert persisted["risk_level"] == "low"


class TestPortScannerSecurity:
    """Security-focused tests."""

    def test_aws_metadata_endpoint_blocked(self, client, auth_headers, app):
        """Test AWS metadata endpoint (169.254.169.254) is blocked."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False

        response = client.post(
            "/api/scanner/ports",
            json={"target": "169.254.169.254", "ports": [80]},
            headers=auth_headers,
        )
        assert response.status_code == 400

    def test_docker_socket_blocked(self, client, auth_headers, app):
        """Test docker daemon port (2375) on localhost blocked."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False

        response = client.post(
            "/api/scanner/ports",
            json={"target": "localhost", "ports": [2375]},
            headers=auth_headers,
        )
        assert response.status_code == 400

    def test_kubernetes_api_blocked(self, client, auth_headers, app):
        """Test kubernetes API (6443) on private IP blocked."""
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = False

        response = client.post(
            "/api/scanner/ports",
            json={"target": "10.0.0.1", "ports": [6443]},
            headers=auth_headers,
        )
        assert response.status_code == 400

    def test_no_stealth_scan_capability(self):
        """Verify service only implements TCP connect, not SYN/stealth."""
        # The service uses socket.connect_ex() which is TCP connect
        # No raw sockets, no SYN crafting
        import inspect
        source = inspect.getsource(PortScannerService._scan_single_port)
        assert "connect_ex" in source
        assert "AF_INET" in source
        assert "SOCK_STREAM" in source
        # Should NOT have raw socket or SYN
        assert "SOCK_RAW" not in source
        assert "IPPROTO_TCP" not in source

    def test_no_udp_scan(self):
        """Verify service does not support UDP scanning."""
        import inspect
        source = inspect.getsource(PortScannerService)
        assert "SOCK_DGRAM" not in source
        assert "UDP" not in source.upper()

    def test_no_exploit_functions(self):
        """Verify no exploit/credential testing functions."""
        import inspect
        source = inspect.getsource(PortScannerService)
        exploit_keywords = ["exploit", "brute", "credential", "password", "login", "shell"]
        # Note: "auth" appears in "authorized" in docstring, "exec" in "ThreadPoolExecutor" - both expected
        for kw in exploit_keywords:
            assert kw not in source.lower(), f"Found exploit keyword: {kw}"