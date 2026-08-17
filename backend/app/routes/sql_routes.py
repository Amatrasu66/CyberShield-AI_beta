"""
SQL Injection Playground Routes (Educational).

POST /api/sql/demo          - illustrative demo (public, non-executing)
POST /api/sql/run           - run one fixed sandbox scenario (authenticated)
GET  /api/sql/scenarios     - list the fixed scenario catalog (authenticated)

No SQL is ever executed by these routes. ``/api/sql/run`` is a thin
authenticated transport layer over ``SQLLabService`` (Phase 1): the route only
validates the request shape at the HTTP boundary and delegates the entire,
fully isolated in-memory SQLite sandbox to the service.
"""

from flask import Blueprint, current_app

from ..middleware.auth_middleware import require_auth
from ..services import SQLPlaygroundService
from ..services.sql_lab_service import SQL_PAYLOAD_MAX_LENGTH, SQLLabService
from ..utils.helpers import success_response
from ..utils.validators import require_json, validate_string

sql_bp = Blueprint("sql", __name__)

# Scenario identifiers are short, fixed keys in the sandbox catalog; anything
# longer than this can never be a valid scenario id.
_SCENARIO_ID_MAX_LENGTH = 64


def _sql_payload_max():
    return current_app.config.get("SQL_PAYLOAD_MAX_LENGTH", SQL_PAYLOAD_MAX_LENGTH)


@sql_bp.post("/demo")
def run_demo():
    data = require_json()
    input_value = data.get("input")
    input_value = SQLPlaygroundService.validate_input(
        input_value, max_length=current_app.config.get("CRYPTO_MAX_INPUT_LENGTH", 4096)
    )
    result = SQLPlaygroundService.run_demo(input_value)
    return success_response(result, "Safe demo completed")


@sql_bp.post("/run")
@require_auth
def run_sql_demo():
    data = require_json()
    scenario = validate_string(data.get("scenario"), "scenario", _SCENARIO_ID_MAX_LENGTH)
    payload = validate_string(data.get("payload"), "payload", _sql_payload_max())
    result = SQLLabService.run_scenario(scenario, payload)
    return success_response(result, "SQL playground demo completed")


@sql_bp.get("/scenarios")
@require_auth
def get_sql_scenarios():
    scenarios = SQLLabService.available_scenarios()
    return success_response(scenarios, "SQL playground scenarios retrieved")
