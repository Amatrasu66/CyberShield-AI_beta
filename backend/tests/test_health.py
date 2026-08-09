"""Tests for the health and version endpoints."""


def test_health_returns_ok(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.get_json()
    assert body["success"] is True
    data = body["data"]
    assert data["status"] == "ok"
    assert data["service"]
    assert data["version"]
    assert data["environment"] == "testing"
    assert data["dependencies"]["database_connected"] is False


def test_health_reports_database_not_configured(app, client):
    response = client.get("/api/health")
    body = response.get_json()
    assert body["data"]["dependencies"]["database"] == "not_configured"


def test_version_returns_api_metadata(client):
    response = client.get("/api/version")
    assert response.status_code == 200
    body = response.get_json()
    assert body["success"] is True
    data = body["data"]
    assert data["name"] == "CyberShield AI API"
    assert data["version"] == "1.0"
    assert data["api_url_prefix"] == "/api"
    assert data["environment"] == "testing"
