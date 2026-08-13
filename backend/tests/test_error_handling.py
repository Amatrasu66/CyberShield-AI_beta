"""Tests for centralized error handling, response format, and security headers."""


def test_404_returns_json_envelope(client):
    response = client.get("/api/does-not-exist")
    assert response.status_code == 404
    body = response.get_json()
    assert body["success"] is False
    assert body["error"]["code"] == "NOT_FOUND"
    assert body["message"]


def test_405_returns_json_envelope(client):
    response = client.get("/api/password/analyze")
    assert response.status_code == 405
    body = response.get_json()
    assert body["success"] is False
    assert body["error"]["code"] == "METHOD_NOT_ALLOWED"


def test_malformed_json_returns_400(client, auth_headers):
    response = client.post(
        "/api/password/analyze",
        data="{invalid json",
        content_type="application/json",
        headers=auth_headers,
    )
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "INVALID_JSON"


def test_non_json_content_type_returns_400(client, auth_headers):
    response = client.post(
        "/api/password/analyze",
        data="hello",
        content_type="text/plain",
        headers=auth_headers,
    )
    assert response.status_code in {400, 415}
    assert response.get_json()["success"] is False


def test_payload_too_large_returns_413(app, client, auth_headers):
    app.config["MAX_CONTENT_LENGTH"] = 1000
    response = client.post(
        "/api/email/analyze",
        json={"content": "a" * 5000},
        headers=auth_headers,
    )
    assert response.status_code == 413
    assert response.get_json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_500_hides_internal_details(client, app):
    @app.route("/api/test-crash")
    def crash():
        raise RuntimeError("sensitive internal detail")

    response = client.get("/api/test-crash")
    assert response.status_code == 500
    body = response.get_json()
    assert body["error"]["code"] == "INTERNAL_ERROR"
    assert "sensitive internal detail" not in str(body)


def test_success_envelope_shape(client):
    response = client.get("/api/health")
    body = response.get_json()
    assert body["success"] is True
    assert "data" in body
    assert "message" in body


def test_security_headers_present(client):
    response = client.get("/api/health")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Content-Security-Policy")
    assert response.headers.get("Referrer-Policy") == "no-referrer"


def test_cors_header_applied(app, client):
    response = client.get("/api/health", headers={"Origin": "http://localhost:3000"})
    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") == "http://localhost:3000"
