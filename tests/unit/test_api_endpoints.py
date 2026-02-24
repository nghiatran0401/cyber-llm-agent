"""Unit tests for FastAPI endpoint envelope and routing."""

import json

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

    monkeypatch.setattr("services.api.main.Settings.sandbox_enabled", lambda: True)
    monkeypatch.setattr("services.api.main.get_sandbox_scenarios", lambda: ["sqli", "xss"])
    response = client.get("/api/v1/sandbox/scenarios")

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["result"] == ["sqli", "xss"]
    assert body["meta"]["api_version"] == "v1"


def test_sandbox_endpoint_returns_403_when_disabled(monkeypatch):
    client = TestClient(app)
    monkeypatch.setattr("services.api.main.Settings.sandbox_enabled", lambda: False)

    response = client.get("/api/v1/sandbox/scenarios")
    assert response.status_code == 403
    body = response.json()
    assert body["ok"] is False
    assert body["error"]["code"] == "HTTP_403"


def test_workspace_stream_emits_trace_and_final(monkeypatch):
    client = TestClient(app)

    def _fake_run_workspace_with_progress(*, task, mode, user_input, on_step, session_id=None):
        assert task == "chat"
        assert mode == "g1"
        assert user_input == "hello"
        on_step(
            type(
                "StepLike",
                (),
                {
                    "model_dump": lambda self: {
                        "step": "InputPreparation",
                        "what_it_does": "Prepare request.",
                        "prompt_preview": "hello",
                        "input_summary": "hello",
                        "output_summary": "ok",
                    }
                },
            )()
        )
        return "final answer", "gpt-4o-mini"

    monkeypatch.setattr("services.api.main.run_workspace_with_progress", _fake_run_workspace_with_progress)

    with client.stream(
        "POST",
        "/api/v1/workspace/stream",
        json={"task": "chat", "mode": "g1", "input": "hello"},
    ) as response:
        assert response.status_code == 200
        events = []
        for line in response.iter_lines():
            if line and line.startswith("data: "):
                events.append(json.loads(line.replace("data: ", "")))

    assert any(event["type"] == "trace" for event in events)
    assert any(event["type"] == "final" and event["result"] == "final answer" for event in events)
    assert any(event["type"] == "done" for event in events)
