"""
SQL Injection Playground Routes (Educational).

POST /api/sql/demo

No SQL is ever executed; the endpoint only renders illustrative comparisons
between vulnerable concatenation and parameterized queries.
"""

from flask import Blueprint, current_app

from ..services import SQLPlaygroundService
from ..utils.helpers import success_response
from ..utils.validators import require_json

sql_bp = Blueprint("sql", __name__)


@sql_bp.post("/demo")
def run_demo():
    data = require_json()
    input_value = data.get("input")
    input_value = SQLPlaygroundService.validate_input(
        input_value, max_length=current_app.config.get("CRYPTO_MAX_INPUT_LENGTH", 4096)
    )
    result = SQLPlaygroundService.run_demo(input_value)
    return success_response(result, "Safe demo completed")
