"""
Input validation and sanitization helpers.

Every external input reaching the backend is validated here before it reaches
business logic. Validators are pure and deterministic so they are unit-testable.
"""

import ipaddress
import re
import socket
from urllib.parse import urlsplit

from flask import current_app, request

from ..errors import PayloadTooLargeError, ValidationError

URL_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^\s]+$")
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def require_json():
    """Ensure the current request carries a JSON body and return it.

    Raises a :class:`ValidationError` with a consistent envelope otherwise.
    """
    from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

    try:
        data = request.get_json(silent=False, force=False)
    except (BadRequest, RequestEntityTooLarge):
        raise
    except Exception:
        raise ValidationError("Request body must be valid JSON", details={"field": "body"})
    if not isinstance(data, dict):
        raise ValidationError("Request body must be a JSON object", details={"field": "body"})
    return data


def check_payload_size_limit(size: int, limit_key: str = "MAX_CONTENT_LENGTH"):
    """Raise if the given size exceeds the configured limit."""
    limit = int(current_app.config.get(limit_key, 1_000_000) or 1_000_000)
    if size is not None and size > limit:
        raise PayloadTooLargeError(
            f"Input exceeds the configured limit of {limit} characters",
            details={"limit": limit},
        )


def validate_string(value, field: str, max_length: int, min_length: int = 0):
    """Validate that ``value`` is a string within length bounds."""
    if not isinstance(value, str):
        raise ValidationError(
            f"'{field}' must be a string", details={"field": field, "type": type(value).__name__}
        )
    if len(value) < min_length:
        raise ValidationError(
            f"'{field}' must be at least {min_length} characters",
            details={"field": field, "min_length": min_length},
        )
    if len(value) > max_length:
        raise ValidationError(
            f"'{field}' exceeds the maximum length of {max_length} characters",
            details={"field": field, "max_length": max_length},
        )
    return value


def validate_url(url: str, max_length: int = 2048) -> str:
    """Validate a URL suitable for the educational scanner.

    Only ``http``/``https`` schemes with a real hostname are accepted. URLs
    embedding credentials are rejected. Returns the normalized URL.
    """
    from urllib.parse import urlsplit

    validate_string(url, "url", max_length)
    url = url.strip()

    if not URL_REGEX.match(url):
        raise ValidationError(
            "URL must use the http:// or https:// scheme",
            details={"field": "url"},
        )

    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValidationError(
            "Only http:// and https:// URLs are allowed",
            details={"field": "url", "scheme": parsed.scheme},
        )
    if not parsed.hostname:
        raise ValidationError("URL must include a hostname", details={"field": "url"})
    if parsed.username or parsed.password:
        raise ValidationError(
            "URLs must not embed credentials", details={"field": "url"}
        )
    try:
        if parsed.port is not None and not (0 < parsed.port < 65536):
            raise ValidationError("URL contains an invalid port", details={"field": "url"})
    except ValueError:
        raise ValidationError("URL contains an invalid port", details={"field": "url"})

    return url


def is_private_host(url: str) -> bool:
    """Return True if the URL hostname resolves to a private/reserved address.

    Used to prevent the educational scanner from being abused as an SSRF tool.
    Hostnames that cannot be resolved return False so the scanner's own
    connection-error handling reports an unreachable target.
    """
    import socket

    from urllib.parse import urlsplit

    hostname = urlsplit(url).hostname
    if not hostname:
        return True
    try:
        info = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for addr in info:
        ip = ipaddress.ip_address(addr[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return True
    return False


def validate_email(email: str) -> str:
    """Validate an email address format."""
    validate_string(email, "email", 254)
    email = email.strip()
    if not EMAIL_REGEX.match(email):
        raise ValidationError(
            "Invalid email address format", details={"field": "email"}
        )
    return email


def validate_password_input(password, max_length: int = 4096) -> str:
    """Validate the password submitted for analysis (format only).

    The password is never stored and never logged.
    """
    return validate_string(password, "password", max_length)


# --- Port Scanner Validators ------------------------------------------------

# Well-known port to service name mapping (top 100 + common)
PORT_SERVICE_MAP = {
    1: "tcpmux",
    7: "echo",
    9: "discard",
    13: "daytime",
    17: "qotd",
    19: "chargen",
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    37: "time",
    42: "nameserver",
    43: "whois",
    53: "dns",
    67: "dhcp-server",
    68: "dhcp-client",
    69: "tftp",
    79: "finger",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    113: "ident",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    179: "bgp",
    199: "smux",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    512: "exec",
    513: "login",
    514: "shell",
    515: "printer",
    543: "klogin",
    544: "kshell",
    548: "afp",
    554: "rtsp",
    587: "submission",
    593: "http-rpc-epmap",
    631: "ipp",
    636: "ldaps",
    873: "rsync",
    902: "vmware-auth",
    989: "ftps-data",
    990: "ftps",
    993: "imaps",
    995: "pop3s",
    1024: "reserved",
    1025: "msrpc",
    1026: "msrpc",
    1027: "msrpc",
    1028: "msrpc",
    1029: "msrpc",
    1080: "socks",
    1194: "openvpn",
    1433: "ms-sql-s",
    1434: "ms-sql-m",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    2082: "cpanel",
    2083: "cpanel-ssl",
    2086: "whm",
    2087: "whm-ssl",
    2121: "ftp-alt",
    2222: "ssh-alt",
    2375: "docker",
    2376: "docker-ssl",
    2483: "oracle-db",
    2484: "oracle-db-ssl",
    3000: "dev-server",
    3128: "squid",
    3306: "mysql",
    3389: "rdp",
    3690: "svn",
    4000: "dev-alt",
    4443: "https-alt",
    4567: "sinatra",
    4786: "smart-install",
    5000: "dev-server",
    5060: "sip",
    5061: "sip-tls",
    5432: "postgresql",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    5984: "couchdb",
    6000: "x11",
    6379: "redis",
    6443: "kubernetes",
    6667: "irc",
    7000: "dev-alt",
    7001: "weblogic",
    8000: "dev-server",
    8008: "http-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8086: "influxdb",
    8088: "http-alt",
    8090: "http-alt",
    8140: "puppet",
    8443: "https-alt",
    8888: "dev-server",
    9000: "dev-alt",
    9090: "http-alt",
    9200: "elasticsearch",
    9300: "elasticsearch",
    10000: "webmin",
    11211: "memcached",
    15672: "rabbitmq-mgmt",
    27017: "mongodb",
    27018: "mongodb",
    27019: "mongodb",
}


# Quick scan profile: top 20 most common ports
QUICK_SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 8080,
]

# Common scan profile: top 100 ports (includes quick scan)
COMMON_SCAN_PORTS = [
    1, 7, 9, 13, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 67, 68, 69, 79, 80,
    88, 110, 111, 113, 119, 123, 135, 137, 138, 139, 143, 161, 162, 179, 199,
    389, 443, 445, 465, 512, 513, 514, 515, 543, 544, 548, 554, 587, 593, 631,
    636, 873, 902, 989, 990, 993, 995, 1080, 1194, 1433, 1434, 1521, 1723,
    2049, 2082, 2083, 2086, 2087, 2121, 2222, 2375, 2376, 2483, 2484, 3000,
    3128, 3306, 3389, 3690, 4000, 4443, 4567, 4786, 5000, 5060, 5061, 5432,
    5601, 5672, 5900, 5984, 6000, 6379, 6443, 6667, 7000, 7001, 8000, 8008,
    8080, 8081, 8086, 8088, 8090, 8140, 8443, 8888, 9000, 9090, 9200, 9300,
    10000, 11211, 15672, 27017, 27018, 27019,
]

# Maximum ports allowed per scan request
DEFAULT_MAX_PORTS = 100


def get_service_name(port: int) -> str:
    """Return the well-known service name for a port, or 'unknown'."""
    return PORT_SERVICE_MAP.get(port, "unknown")


def validate_port_list(ports, max_ports: int = DEFAULT_MAX_PORTS) -> list[int]:
    """Validate and normalize a list of port numbers.

    Args:
        ports: Iterable of port numbers (int) or port strings.
        max_ports: Maximum number of unique ports allowed.

    Returns:
        Sorted list of unique valid port numbers.

    Raises:
        ValidationError: If any port is invalid, out of range, or too many ports.
    """
    if ports is None:
        raise ValidationError("Port list is required", details={"field": "ports"})

    try:
        iter(ports)
    except TypeError:
        raise ValidationError(
            "'ports' must be a list or array", details={"field": "ports", "type": type(ports).__name__}
        )

    validated = []
    seen = set()
    for p in ports:
        try:
            port = int(p)
        except (ValueError, TypeError):
            raise ValidationError(
                f"Invalid port value: {p!r}", details={"field": "ports", "value": p}
            )
        if not (1 <= port <= 65535):
            raise ValidationError(
                f"Port {port} out of range (1-65535)", details={"field": "ports", "port": port}
            )
        if port not in seen:
            seen.add(port)
            validated.append(port)

    if len(validated) > max_ports:
        raise ValidationError(
            f"Too many ports: {len(validated)} (maximum {max_ports})",
            details={"field": "ports", "count": len(validated), "max": max_ports},
        )

    return sorted(validated)


def resolve_scan_ports(ports=None, profile=None, max_ports: int = DEFAULT_MAX_PORTS) -> list[int]:
    """Resolve the final port list from explicit ports and/or profile.

    Args:
        ports: Explicit list of port numbers.
        profile: Scan profile name ('quick' or 'common').
        max_ports: Maximum ports allowed.

    Returns:
        Sorted list of unique port numbers to scan.

    Raises:
        ValidationError: If both ports and profile are missing, or profile is invalid.
    """
    if ports is not None and profile is not None:
        raise ValidationError(
            "Specify either 'ports' or 'profile', not both",
            details={"field": "ports/profile"},
        )

    if profile is not None:
        if profile == "quick":
            base_ports = QUICK_SCAN_PORTS
        elif profile == "common":
            base_ports = COMMON_SCAN_PORTS
        else:
            raise ValidationError(
                f"Invalid profile: {profile}. Use 'quick' or 'common'",
                details={"field": "profile", "value": profile},
            )
        return base_ports[:max_ports]

    if ports is not None:
        return validate_port_list(ports, max_ports)

    raise ValidationError(
        "Either 'ports' (list) or 'profile' ('quick'|'common') is required",
        details={"field": "ports/profile"},
    )


def validate_hostname_or_ip(target: str, max_length: int = 255) -> str:
    """Validate a hostname or IP address for port scanning.

    Unlike validate_url, this accepts bare hostnames/IPs without a scheme.
    Returns the normalized target (lowercase hostname, or IP as string).

    Raises:
        ValidationError: If target is invalid, empty, or too long.
    """
    validate_string(target, "target", max_length, min_length=1)
    target = target.strip().lower()

    # Reject URLs with schemes
    if "://" in target:
        raise ValidationError(
            "Target must be a hostname or IP address (no scheme)",
            details={"field": "target"},
        )

    # Reject credentials
    if "@" in target:
        raise ValidationError(
            "Target must not contain credentials", details={"field": "target"}
        )

    # Bracketed IPv6 literal: [2001:db8::1] or [::1]:8080
    if target.startswith("[") and "]" in target:
        bracket_end = target.index("]")
        inner = target[1:bracket_end]
        try:
            ipaddress.ip_address(inner)
        except ValueError:
            raise ValidationError("Invalid IPv6 address", details={"field": "target"})
        target = inner
        # Ignore trailing :port after bracket (e.g. [::1]:8080) — target is host only
    else:
        # Detect bare IPv6 with port without brackets (e.g., 2001:db8::1:80) — reject before bare IP check
        if target.count(":") > 1 and ":" in target:
            potential_host, potential_port = target.rsplit(":", 1)
            if potential_port.isdigit():
                try:
                    ipaddress.ip_address(potential_host)
                    raise ValidationError(
                        "IPv6 addresses must be enclosed in brackets (e.g., [::1])",
                        details={"field": "target"},
                    )
                except ValueError:
                    pass
        # Bare IP literal (IPv4 or IPv6) — must be checked before host:port splitting
        # so bare IPv6 like 2001:4860:4860::8888 is not truncated at first colon
        try:
            parsed = ipaddress.ip_address(target)
            return str(parsed)
        except ValueError:
            pass
        # Hostname with optional :port (single colon only). Bare IPv6 already returned
        # above, so any remaining multiple colons is malformed IPv6 without brackets.
        if ":" in target:
            if target.count(":") > 1:
                raise ValidationError("Invalid IPv6 address", details={"field": "target"})
            # Single colon -> hostname:port or IPv4:port
            host_part = target.split(":", 1)[0]
            # Validate port part is numeric if present
            port_part = target.split(":", 1)[1]
            if port_part and not port_part.isdigit():
                raise ValidationError(
                    "Target must be a valid hostname or IP address",
                    details={"field": "target", "value": target},
                )
            if port_part and port_part.isdigit():
                p = int(port_part)
                if not (1 <= p <= 65535):
                    raise ValidationError(
                        "Target must be a valid hostname or IP address",
                        details={"field": "target", "value": target},
                    )
            target = host_part
            if not target:
                raise ValidationError(
                    "Target must be a valid hostname or IP address",
                    details={"field": "target", "value": target},
                )

    # Strip trailing dot from FQDN
    if target.endswith("."):
        target = target[:-1]

    # Now target should be a bare hostname or IP
    # Validate hostname format (RFC 1123)
    if not _is_valid_hostname(target) and not _is_valid_ip(target):
        raise ValidationError(
            "Target must be a valid hostname or IP address",
            details={"field": "target", "value": target},
        )

    return target


def _is_valid_hostname(hostname: str) -> bool:
    """Check if string is a valid hostname (RFC 1123)."""
    if len(hostname) > 253:
        return False
    # Allow trailing dot for FQDN
    if hostname.endswith("."):
        hostname = hostname[:-1]
    labels = hostname.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", label, re.IGNORECASE):
            return False
    return True


def _is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_hostname(target: str) -> bool:
    """Return True if the target hostname/IP resolves to a private/reserved address.

    Used to prevent the port scanner from being abused as an SSRF tool.
    Unlike is_private_host, this accepts bare hostnames/IPs (no URL scheme).
    """
    import socket

    # If it's already an IP, check directly
    try:
        ip = ipaddress.ip_address(target)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    except ValueError:
        pass

    # Resolve hostname
    try:
        info = socket.getaddrinfo(target, None)
    except socket.gaierror:
        # Unresolvable hostnames are not blocked here; scanner will report unreachable
        return False

    for addr in info:
        try:
            ip = ipaddress.ip_address(addr[4][0])
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return True
    return False


# --- IP Reputation Validators ------------------------------------------------

def validate_ip_address(ip: str, max_length: int = 45) -> str:
    """Validate a single IP address (v4 or v6) strictly.

    Returns normalized string form. Raises ValidationError otherwise.
    """
    validate_string(ip, "ip", max_length, min_length=1)
    ip = ip.strip()
    # Strip brackets if present (e.g. [::1])
    if ip.startswith("[") and ip.endswith("]"):
        ip = ip[1:-1]
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        raise ValidationError("Invalid IP address", details={"field": "ip", "value": ip})
    return str(parsed)


def is_private_ip(ip: str) -> bool:
    """Return True if IP is private/loopback/link-local/reserved/multicast/unspecified."""
    try:
        parsed = ipaddress.ip_address(ip.strip())
    except ValueError:
        # Non-IP considered not private here; caller should validate separately
        return False
    return (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_reserved
        or parsed.is_multicast
        or parsed.is_unspecified
    )
