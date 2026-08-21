"""
Port Scanner Routes.

POST /api/scanner/ports
GET  /api/scanner/ports/history
GET  /api/scanner/ports/history/<scan_id>
"""

from flask import Blueprint, current_app, request

from ..middleware import get_current_user_id, require_auth
from ..services import PortScannerService
from ..utils.helpers import success_response
from ..utils.validators import require_json

port_bp = Blueprint("port", __name__)


@port_bp.post("/ports")
@require_auth
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