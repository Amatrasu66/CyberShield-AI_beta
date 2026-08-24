"""
Port Scanner Routes.

POST /api/scanner/ports
GET  /api/scanner/ports/history
GET  /api/scanner/ports/history/<scan_id>
GET  /api/scanner/ip-reputation/<ip>
POST /api/scanner/ip-reputation
"""

from flask import Blueprint, current_app, request

from ..middleware import get_current_user_id, require_auth
from ..middleware.rate_limiter import rate_limit
from ..services import PortScannerService
from ..services.ip_reputation_service import IPReputationService
from ..utils.helpers import success_response
from ..utils.validators import require_json
from ..errors import ValidationError

port_bp = Blueprint("port", __name__)


@port_bp.post("/ports")
@require_auth
@rate_limit("port_scan")
def scan_ports():
    data = require_json()
    target = data.get("target")
    ports = data.get("ports")
    profile = data.get("profile")

    if not target:
        from ..errors import ValidationError
        raise ValidationError(
            "'target' is required (hostname or IP address)",
            details={"field": "target"},
        )

    # Validate target before any network operation
    from ..utils.validators import validate_hostname_or_ip
    target = validate_hostname_or_ip(target, max_length=current_app.config.get("URL_MAX_LENGTH", 2048))

    result = PortScannerService.scan_ports(
        target=target,
        ports=ports,
        profile=profile,
        user_id=get_current_user_id(),
    )

    # Convert dataclass to dict for JSON serialization
    result_dict = {
        "target": result.target,
        "resolved_ip": result.resolved_ip,
        "scan_duration_ms": result.scan_duration_ms,
        "ports_scanned": result.ports_scanned,
        "open_ports": [
            {
                "port": p.port,
                "service": p.service,
                "state": p.state,
                "banner": p.banner,
            }
            for p in result.open_ports
        ],
        "closed_ports": result.closed_ports,
        "filtered_ports": result.filtered_ports,
        "summary": result.summary,
        "risk_level": result.risk_level,
        "ip_reputation": result.ip_reputation,
        "threat_assessment": result.threat_assessment,
    }

    return success_response(result_dict, "Port scan completed")


@port_bp.get("/ports/history")
@require_auth
def list_port_scan_history():
    """List the authenticated user's previous port scans (newest first)."""
    page = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 20, type=int)

    history = PortScannerService.get_scan_history(
        user_id=get_current_user_id(),
        page=page,
        limit=limit,
    )

    return success_response(
        history["scans"],
        "Port scan history retrieved",
        meta={
            "total": history["total"],
            "page": history["page"],
            "limit": history["limit"],
        },
    )


@port_bp.get("/ports/history/<scan_id>")
@require_auth
def get_port_scan_detail(scan_id: str):
    """Return a single historical port scan for the authenticated user."""
    scan = PortScannerService.get_scan_detail(
        user_id=get_current_user_id(),
        scan_id=scan_id,
    )

    return success_response(scan, "Port scan detail retrieved")


@port_bp.get("/ip-reputation/<path:ip>")
@require_auth
@rate_limit("ip_reputation")
def get_ip_reputation(ip: str):
    """Retrieve IP reputation for a single IP (authenticated).

    Strict validation; private IPs blocked before external call.
    Returns normalized result with reputation states:
    unknown | clean | suspicious | malicious | unavailable
    """
    # ip comes from URL path — validate strictly as IP
    from ..utils.validators import validate_ip_address, is_private_ip

    # Flask decodes URL; strip
    ip = (ip or "").strip()
    normalized = validate_ip_address(ip)
    if is_private_ip(normalized):
        raise ValidationError(
            "Private or reserved IP addresses cannot be checked for reputation",
            details={"field": "ip"},
        )

    result = IPReputationService.check_ip(normalized)
    return success_response(result.to_dict(), "IP reputation check completed")


@port_bp.post("/ip-reputation")
@require_auth
@rate_limit("ip_reputation")
def post_ip_reputation():
    """Check reputation for IP or hostname via POST body.

    Accepts either {"ip": "1.2.3.4"} or {"target": "example.com"}.
    Never accepts user_id from client; uses JWT for auth only.
    """
    data = require_json()
    ip = data.get("ip")
    target = data.get("target")

    if ip and target:
        raise ValidationError("Provide either 'ip' or 'target', not both", details={"field": "ip/target"})
    if ip:
        from ..utils.validators import validate_ip_address, is_private_ip
        normalized = validate_ip_address(str(ip))
        if is_private_ip(normalized):
            raise ValidationError(
                "Private or reserved IP addresses cannot be checked for reputation",
                details={"field": "ip"},
            )
        result = IPReputationService.check_ip(normalized)
        return success_response(result.to_dict(), "IP reputation check completed")
    if target:
        # Delegates hostname resolution and private blocking to service
        result = IPReputationService.check_target(str(target))
        return success_response(result.to_dict(), "IP reputation check completed")

    raise ValidationError("Provide 'ip' or 'target' in request body", details={"field": "ip/target"})
