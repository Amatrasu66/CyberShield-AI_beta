"""
Port Scanner Service (Educational, TCP Connect Only).

Performs a bounded TCP connect port scan against a target host:
- Validates target hostname/IP before ANY socket connection
- Reuses existing SSRF/private-host protections (is_private_hostname)
- Supports explicit ports or 'quick'/'common' profiles
- Maximum 100 ports per request (configurable)
- Per-port connect timeout and total scan timeout
- Bounded concurrency (semaphore)
- Returns open/closed results with port, service name, and safe/truncated banner
- Risk scoring based on detected open ports
- Persists completed scans to Supabase for authenticated users

Safety constraints:
- TCP connect scan only (no SYN/stealth, no UDP, no evasion)
- No exploitation, no credential testing, no auth bypass
- Private/loopback/link-local/reserved IPs blocked by default
- Short timeouts, low concurrency, banner truncation
- Explicit port limit
"""

import json
import socket
import time
import concurrent.futures
from dataclasses import dataclass
from typing import Optional

from ..config import get_config
from ..database import get_user_supabase_client
from ..errors import NotFoundError, ServiceUnavailableError, ValidationError
from ..middleware.auth_middleware import get_current_access_token
from ..utils.validators import (
    is_private_hostname,
    resolve_scan_ports,
    validate_hostname_or_ip,
    get_service_name,
    DEFAULT_MAX_PORTS,
)


# Risk port categories for scoring
CRITICAL_RISK_PORTS = {22, 23, 3389, 5900, 5901, 5985, 5986}  # SSH, Telnet, RDP, VNC, WinRM
HIGH_RISK_PORTS = {135, 139, 445, 1433, 1521, 3306, 5432, 6379, 27017, 27018, 27019}  # RPC, SMB, DBs
MEDIUM_RISK_PORTS = {21, 25, 53, 80, 110, 111, 143, 443, 465, 587, 993, 995, 1723, 8080, 8443, 8000, 8081, 8888, 9000, 9090}  # Web, mail, proxy


@dataclass
class PortResult:
    """Result of scanning a single port."""
    port: int
    service: str
    state: str  # "open" | "closed" | "filtered"
    banner: str = ""


@dataclass
class ScanResult:
    """Aggregated scan result."""
    target: str
    resolved_ip: str
    scan_duration_ms: int
    ports_scanned: int
    open_ports: list[PortResult]
    closed_ports: int
    filtered_ports: int
    summary: str
    risk_level: str  # "low" | "medium" | "high" | "critical"


class PortScannerService:
    """Bounded TCP connect port scanner for authorized assessment."""

    @staticmethod
    def scan_ports(
        target: str,
        ports: list[int] = None,
        profile: str = None,
        config: dict = None,
        user_id: str = None,
    ) -> ScanResult:
        """Scan target for open ports using TCP connect.

        Args:
            target: Hostname or IP address (no scheme).
            ports: Explicit list of ports to scan.
            profile: Scan profile ('quick' or 'common').
            config: Flask app config for limits/timeouts.

        Returns:
            ScanResult with per-port findings and risk level.

        Raises:
            ValidationError: For invalid target, ports, or private host.
        """
        from flask import current_app

        cfg = config or current_app.config

        # Validate target BEFORE any socket connection
        target = validate_hostname_or_ip(target, max_length=cfg.get("URL_MAX_LENGTH", 2048))

        # SSRF protection: block private/loopback/link-local/reserved
        if not cfg.get("PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES", False) and is_private_hostname(target):
            raise ValidationError(
                "Target resolves to a private or loopback address and is refused "
                "to prevent scanner abuse.",
                details={"field": "target"},
            )

        # Resolve ports from explicit list or profile
        max_ports = int(cfg.get("PORT_SCANNER_MAX_PORTS", DEFAULT_MAX_PORTS))
        port_list = resolve_scan_ports(ports, profile, max_ports)

        # Resolve target to IP for scanning and display
        resolved_ip = PortScannerService._resolve_target(target, cfg)

        # Perform the scan with bounded concurrency and timeouts
        started = time.perf_counter()
        open_ports = PortScannerService._scan_port_list(
            target, resolved_ip, port_list, cfg
        )
        duration_ms = round((time.perf_counter() - started) * 1000)

        # Count states
        open_count = sum(1 for p in open_ports if p.state == "open")
        closed_count = sum(1 for p in open_ports if p.state == "closed")
        filtered_count = sum(1 for p in open_ports if p.state == "filtered")

        # Risk scoring based on open ports
        risk_level = PortScannerService._calculate_risk_level(open_ports)

        # Build summary
        summary_parts = []
        if open_count:
            summary_parts.append(f"{open_count} open")
        if closed_count:
            summary_parts.append(f"{closed_count} closed")
        if filtered_count:
            summary_parts.append(f"{filtered_count} filtered")
        summary = f"Scanned {len(port_list)} ports: {', '.join(summary_parts) or 'none'}"

        result = ScanResult(
            target=target,
            resolved_ip=resolved_ip,
            scan_duration_ms=duration_ms,
            ports_scanned=len(port_list),
            open_ports=open_ports,
            closed_ports=closed_count,
            filtered_ports=filtered_count,
            summary=summary,
            risk_level=risk_level,
        )

        # Persist completed scan for authenticated user
        PortScannerService._persist_scan(user_id, target, result)

        return result

    @staticmethod
    def _resolve_target(target: str, cfg: dict) -> str:
        """Resolve target hostname to IP address."""
        try:
            # Use getaddrinfo to support both IPv4 and IPv6
            info = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            # Prefer IPv4 for display, but use first result
            for addr in info:
                ip = addr[4][0]
                # Skip IPv6 link-local for display
                if not ip.startswith("fe80::"):
                    return ip
            return info[0][4][0]
        except socket.gaierror:
            # If resolution fails, return target as-is; scan will fail gracefully
            return target

    @staticmethod
    def _scan_port_list(
        target: str, resolved_ip: str, ports: list[int], cfg: dict
    ) -> list[PortResult]:
        """Scan a list of ports with bounded concurrency and timeouts."""
        per_port_timeout = float(cfg.get("PORT_SCANNER_CONNECT_TIMEOUT", 2.0))
        total_timeout = float(cfg.get("PORT_SCANNER_TOTAL_TIMEOUT", 30.0))
        max_concurrency = int(cfg.get("PORT_SCANNER_MAX_CONCURRENCY", 50))
        banner_timeout = float(cfg.get("PORT_SCANNER_BANNER_TIMEOUT", 1.0))
        banner_max_bytes = int(cfg.get("PORT_SCANNER_BANNER_MAX_BYTES", 256))

        # Use ThreadPoolExecutor for bounded concurrency
        results: list[PortResult] = []
        start_time = time.perf_counter()

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrency) as executor:
            # Submit all tasks
            future_to_port = {
                executor.submit(
                    PortScannerService._scan_single_port,
                    target,
                    port,
                    per_port_timeout,
                    banner_timeout,
                    banner_max_bytes,
                ): port
                for port in ports
            }

            # Collect results with total timeout
            for future in concurrent.futures.as_completed(future_to_port, timeout=total_timeout):
                # Check total timeout
                if time.perf_counter() - start_time > total_timeout:
                    # Cancel remaining futures
                    for f in future_to_port:
                        f.cancel()
                    break

                port = future_to_port[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception:
                    # On any error, mark as filtered
                    results.append(PortResult(
                        port=port,
                        service=get_service_name(port),
                        state="filtered",
                        banner="",
                    ))

        return results

    @staticmethod
    def _scan_single_port(
        target: str,
        port: int,
        connect_timeout: float,
        banner_timeout: float,
        banner_max_bytes: int,
    ) -> PortResult:
        """Scan a single port using TCP connect.

        Attempts connection, then tries to read a banner if open.
        """
        service = get_service_name(port)

        try:
            # Create socket with timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(connect_timeout)

            # Try to connect
            result = sock.connect_ex((target, port))

            if result == 0:
                # Connection succeeded - port is open
                banner = ""
                try:
                    # Try to read banner
                    sock.settimeout(banner_timeout)
                    data = sock.recv(banner_max_bytes)
                    if data:
                        # Decode safely, truncate
                        banner = data.decode("utf-8", errors="ignore").strip()
                        # Sanitize: remove control chars except newline/tab
                        banner = "".join(c for c in banner if c.isprintable() or c in "\n\t\r")
                        if len(banner) > banner_max_bytes:
                            banner = banner[:banner_max_bytes] + "..."
                except (socket.timeout, socket.error, UnicodeDecodeError):
                    pass
                finally:
                    sock.close()

                return PortResult(
                    port=port,
                    service=service,
                    state="open",
                    banner=banner,
                )
            else:
                # Connection refused or failed - port is closed
                sock.close()
                return PortResult(
                    port=port,
                    service=service,
                    state="closed",
                    banner="",
                )

        except socket.timeout:
            return PortResult(
                port=port,
                service=service,
                state="filtered",
                banner="",
            )
        except socket.gaierror:
            # Target resolution failed
            return PortResult(
                port=port,
                service=service,
                state="filtered",
                banner="",
            )
        except (socket.error, OSError):
            # Other socket errors
            return PortResult(
                port=port,
                service=service,
                state="filtered",
                banner="",
            )

    @staticmethod
    def _calculate_risk_level(open_ports: list[PortResult]) -> str:
        """Calculate risk level based on open ports."""
        open_port_nums = {p.port for p in open_ports if p.state == "open"}

        if open_port_nums & CRITICAL_RISK_PORTS:
            return "critical"
        if open_port_nums & HIGH_RISK_PORTS:
            return "high"
        if open_port_nums & MEDIUM_RISK_PORTS:
            return "medium"
        return "low"

    # ------------------------------------------------------------ persistence
    @staticmethod
    def _persist_scan(user_id: str, target: str, result: ScanResult) -> None:
        """Persist a completed port scan to ``public.port_scans``.

        Persistence is skipped when there is no authenticated ``user_id`` (e.g.
        direct service use) or when Supabase is not configured. Only completed
        scans are stored. ``user_id`` always comes from the verified
        JWT, never from the client. The row is written through a user-scoped
        client authenticated with the request's access token, so RLS scopes it
        to ``auth.uid()``.
        """
        if not user_id:
            return

        client = get_user_supabase_client(get_current_access_token())
        if client is None:
            return

        # Convert open_ports to JSON-serializable format
        open_ports_data = [
            {
                "port": p.port,
                "service": p.service,
                "state": p.state,
                "banner": p.banner,
            }
            for p in result.open_ports
        ]

        payload = {
            "user_id": user_id,
            "target": target,
            "resolved_ip": result.resolved_ip,
            "ports_scanned": result.ports_scanned,
            "open_ports": open_ports_data,
            "scan_duration_ms": result.scan_duration_ms,
            "risk_level": result.risk_level,
            "status": "completed",
        }

        try:
            client.table("port_scans").insert(payload).execute()
        except Exception as exc:
            raise ServiceUnavailableError(
                "Port scan results could not be stored",
                details={"table": "port_scans", "error": type(exc).__name__},
            )

    # ------------------------------------------------------------ history
    @staticmethod
    def get_scan_history(user_id: str, page: int = 1, limit: int = 20) -> dict:
        """Return the authenticated user's port scan history.

        Args:
            user_id: authenticated user UUID from the verified JWT.
            page: 1-indexed page number.
            limit: results per page (max 50).

        Returns:
            Dict with ``scans`` list and ``total`` count.

        Raises:
            ValidationError: when user_id is missing or parameters are invalid.
            ServiceUnavailableError: when Supabase is unavailable.
        """
        if not user_id:
            raise ValidationError(
                "A valid authenticated user is required",
                details={"field": "user_id"},
            )

        page = max(1, int(page))
        limit = min(50, max(1, int(limit)))
        offset = (page - 1) * limit

        client = get_user_supabase_client(get_current_access_token())
        if client is None:
            raise ServiceUnavailableError(
                "Port scan history is unavailable (Supabase not configured)",
                code="PORT_HISTORY_UNAVAILABLE",
            )

        try:
            # Get total count
            count_result = (
                client.table("port_scans")
                .select("id", count="exact")
                .eq("user_id", user_id)
                .execute()
            )
            total = getattr(count_result, "count", None) or 0

            # Get paginated results (newest first)
            result = (
                client.table("port_scans")
                .select(
                    "id, target, resolved_ip, ports_scanned, open_ports, "
                    "scan_duration_ms, risk_level, status, created_at"
                )
                .eq("user_id", user_id)
                .order("created_at", desc=True)
                .range(offset, offset + limit - 1)
                .execute()
            )
        except Exception as exc:
            raise ServiceUnavailableError(
                "Port scan history could not be retrieved",
                details={"table": "port_scans", "error": type(exc).__name__},
            )

        scans = _extract_data(result)
        # Count open ports from JSONB for each scan
        for scan in scans:
            open_ports = scan.get("open_ports") or []
            scan["open_port_count"] = sum(
                1 for p in open_ports if isinstance(p, dict) and p.get("state") == "open"
            )

        return {"scans": scans, "total": total, "page": page, "limit": limit}

    @staticmethod
    def get_scan_detail(user_id: str, scan_id: str) -> dict:
        """Return a single port scan for the authenticated user.

        Args:
            user_id: authenticated user UUID from the verified JWT.
            scan_id: UUID of the scan to retrieve.

        Returns:
            The scan row with all fields.

        Raises:
            ValidationError: when user_id is missing.
            NotFoundError: when scan_id is missing or the scan is not found.
            ServiceUnavailableError: when Supabase is unavailable.
        """
        if not user_id:
            raise ValidationError(
                "A valid authenticated user is required",
                details={"field": "user_id"},
            )

        if not scan_id or not scan_id.strip():
            raise NotFoundError("Scan ID is required")

        client = get_user_supabase_client(get_current_access_token())
        if client is None:
            raise ServiceUnavailableError(
                "Port scan detail is unavailable (Supabase not configured)",
                code="PORT_DETAIL_UNAVAILABLE",
            )

        try:
            result = (
                client.table("port_scans")
                .select("*")
                .eq("id", scan_id)
                .eq("user_id", user_id)
                .execute()
            )
        except Exception as exc:
            raise ServiceUnavailableError(
                "Port scan detail could not be retrieved",
                details={"table": "port_scans", "error": type(exc).__name__},
            )

        rows = _extract_data(result)
        if not rows:
            raise NotFoundError("Port scan not found")

        scan = rows[0]
        open_ports = scan.get("open_ports") or []
        scan["open_port_count"] = sum(
            1 for p in open_ports if isinstance(p, dict) and p.get("state") == "open"
        )
        scan["closed_port_count"] = sum(
            1 for p in open_ports if isinstance(p, dict) and p.get("state") == "closed"
        )
        scan["filtered_port_count"] = sum(
            1 for p in open_ports if isinstance(p, dict) and p.get("state") == "filtered"
        )
        return scan


def _extract_data(result) -> list:
    """Extract the ``data`` list from a supabase ``execute()`` result."""
    if result is None:
        return []
    if isinstance(result, dict):
        data = result.get("data")
    else:
        data = getattr(result, "data", None)
    return data or []