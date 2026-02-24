"""Unit tests for FastAPI endpoint envelope and routing."""

from fastapi.testclient import TestClient

from services.api.main import app


def test_health_endpoint_returns_standard_envelope():
    client = TestClient(app)
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert "meta" in body
    assert body["meta"]["api_version"] == "v1"
    assert body["error"] is None
    assert body["result"]["status"] == "healthy"


def test_g1_endpoint_uses_service_layer(monkeypatch):
    client = TestClient(app)

    def _fake_run_g1_analysis(user_input: str, session_id=None):
        assert user_input == "test input"
        assert session_id == "s-1"
        return "mocked response", [], "gpt-4o-mini"

    monkeypatch.setattr("services.api.main.run_g1_analysis", _fake_run_g1_analysis)

    response = client.post(
        "/api/v1/analyze/g1",
        json={"input": "test input", "session_id": "s-1", "include_trace": True},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["result"] == "mocked response"
    assert body["meta"]["mode"] == "g1"
    assert body["meta"]["api_version"] == "v1"


def test_sandbox_scenarios_endpoint(monkeypatch):
    client = TestClient(app)

    monkeypatch.setattr("services.api.main.get_sandbox_scenarios", lambda: ["sqli", "xss"])
    response = client.get("/api/v1/sandbox/scenarios")

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["result"] == ["sqli", "xss"]
    assert body["meta"]["api_version"] == "v1"
