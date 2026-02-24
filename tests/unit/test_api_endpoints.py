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
        return "mocked response", [], "gpt-4o-mini", "completed", 1, "security_analysis_v2.txt", 4.2, "strong"

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
    assert body["meta"]["stop_reason"] == "completed"
    assert body["meta"]["steps_used"] == 1
    assert body["meta"]["prompt_version"] == "security_analysis_v2.txt"
    assert body["meta"]["rubric_label"] == "strong"
    assert body["meta"]["run_id"] == body["meta"]["request_id"]
    assert body["meta"]["total_tokens_est"] >= 1


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
        return "final answer", "gpt-4o-mini", "completed", 2

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
    final_event = next(event for event in events if event.get("type") == "final")
    assert final_event["meta"]["stop_reason"] == "completed"
    assert final_event["meta"]["steps_used"] == 2
    assert final_event["meta"]["run_id"]
    assert final_event["meta"]["total_tokens_est"] >= 1


def test_metrics_endpoint_returns_aggregates():
    client = TestClient(app)
    response = client.get("/api/v1/metrics")
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert "requests_total" in body["result"]
    assert "by_endpoint" in body["result"]
    assert "by_stop_reason" in body["result"]


def test_metrics_dashboard_endpoint_returns_summary():
    client = TestClient(app)
    response = client.get("/api/v1/metrics/dashboard")
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert "summary" in body["result"]
    assert "breakdown" in body["result"]
    assert "recent_runs" in body["result"]


def test_auth_middleware_rejects_missing_key(monkeypatch):
    client = TestClient(app)
    monkeypatch.setattr("services.api.main.Settings.API_AUTH_ENABLED", True)
    monkeypatch.setattr("services.api.main.Settings.API_AUTH_KEY", "top-secret")

    response = client.post("/api/v1/analyze/g1", json={"input": "hello"})
    assert response.status_code == 401
    body = response.json()
    assert body["ok"] is False
    assert body["error"]["code"] == "HTTP_401"


def test_rate_limit_middleware_returns_429(monkeypatch):
    client = TestClient(app)
    monkeypatch.setattr("services.api.main.Settings.API_AUTH_ENABLED", False)
    monkeypatch.setattr("services.api.main.Settings.API_RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr("services.api.main.Settings.API_RATE_LIMIT_WINDOW_SECONDS", 60)
    monkeypatch.setattr("services.api.main.Settings.API_RATE_LIMIT_MAX_REQUESTS", 1)
    monkeypatch.setattr("services.api.main.run_g1_analysis", lambda *_args, **_kwargs: ("ok", [], "gpt-4o-mini"))
    from services.api.main import _RATE_BUCKETS
    _RATE_BUCKETS.clear()

    first = client.post("/api/v1/analyze/g1", json={"input": "hello"})
    second = client.post("/api/v1/analyze/g1", json={"input": "hello again"})
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers.get("Retry-After")
