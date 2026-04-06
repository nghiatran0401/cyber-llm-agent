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

    monkeypatch.setattr("services.api.routes.run_g1_analysis", _fake_run_g1_analysis)

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
    assert body["meta"]["trace_schema_version"] == "react-trace-v1"
    assert body["meta"]["stop_reason"] == "completed"
    assert body["meta"]["steps_used"] == 1
    assert body["meta"]["prompt_version"] == "security_analysis_v2.txt"
    assert body["meta"]["rubric_label"] == "strong"
    assert body["meta"]["run_id"] == body["meta"]["request_id"]
    assert body["meta"]["total_tokens_est"] >= 1


def test_g2_endpoint_uses_service_layer(monkeypatch):
    client = TestClient(app)

    def _fake_run_g2_analysis(user_input: str):
        assert user_input == "test g2 input"
        return (
            {"final_report": "mocked g2 response", "runtime_budget": {"tool_calls_used": 1}},
            [],
            "gpt-4o-mini",
            "completed",
            2,
            "security_analysis_v2.txt",
            3.7,
            "acceptable",
        )

    monkeypatch.setattr("services.api.routes.run_g2_analysis", _fake_run_g2_analysis)

    response = client.post(
        "/api/v1/analyze/g2",
        json={"input": "test g2 input", "include_trace": True},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["result"]["final_report"] == "mocked g2 response"
    assert body["meta"]["mode"] == "g2"
    assert body["meta"]["stop_reason"] == "completed"
    assert body["meta"]["steps_used"] == 2
    assert body["meta"]["rubric_label"] == "acceptable"


def test_chat_endpoint_supports_g2_mode(monkeypatch):
    client = TestClient(app)

    def _fake_run_chat(user_input: str, mode: str = "g1", session_id=None):
        assert user_input == "chat g2"
        assert mode == "g2"
        return "chat g2 result", [], "gpt-4o-mini", "completed", 2, "security_analysis_v2.txt", 3.4, "acceptable"

    monkeypatch.setattr("services.api.routes.run_chat", _fake_run_chat)

    response = client.post(
        "/api/v1/chat",
        json={"input": "chat g2", "mode": "g2", "include_trace": True},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["result"] == "chat g2 result"
    assert body["meta"]["mode"] == "g2"
    assert body["meta"]["stop_reason"] == "completed"


def test_sandbox_scenarios_endpoint(monkeypatch):
    client = TestClient(app)

    monkeypatch.setattr("services.api.routes.get_sandbox_scenarios", lambda: ["sqli", "xss"])
    response = client.get("/api/v1/sandbox/scenarios")

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["result"] == ["sqli", "xss"]
    assert body["meta"]["api_version"] == "v1"


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

    monkeypatch.setattr("services.api.routes.run_workspace_with_progress", _fake_run_workspace_with_progress)

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
    trace_event = next(event for event in events if event.get("type") == "trace")
    assert trace_event["step"]["run_id"]
    assert trace_event["step"]["step_id"]
    final_event = next(event for event in events if event.get("type") == "final")
    assert final_event["meta"]["stop_reason"] == "completed"
    assert final_event["meta"]["steps_used"] == 2
    assert final_event["meta"]["trace_schema_version"] == "react-trace-v1"
    assert final_event["meta"]["run_id"]
    assert final_event["meta"]["total_tokens_est"] >= 1


def test_workspace_stream_supports_g2_mode(monkeypatch):
    client = TestClient(app)

    def _fake_run_workspace_with_progress(*, task, mode, user_input, on_step, session_id=None):
        assert task == "analyze"
        assert mode == "g2"
        assert user_input == "hello g2"
        on_step(
            type(
                "StepLike",
                (),
                {
                    "model_dump": lambda self: {
                        "step": "Analysis",
                        "what_it_does": "Run g2 analysis.",
                        "prompt_preview": "hello g2",
                        "input_summary": "hello g2",
                        "output_summary": "done",
                    }
                },
            )()
        )
        return "g2 final answer", "gpt-4o-mini", "completed", 3

    monkeypatch.setattr("services.api.routes.run_workspace_with_progress", _fake_run_workspace_with_progress)

    with client.stream(
        "POST",
        "/api/v1/workspace/stream",
        json={"task": "analyze", "mode": "g2", "input": "hello g2"},
    ) as response:
        assert response.status_code == 200
        events = []
        for line in response.iter_lines():
            if line and line.startswith("data: "):
                events.append(json.loads(line.replace("data: ", "")))

    assert any(event["type"] == "trace" for event in events)
    assert any(event["type"] == "final" and event["result"] == "g2 final answer" for event in events)
    final_event = next(event for event in events if event.get("type") == "final")
    assert final_event["meta"]["mode"] == "g2"
    assert final_event["meta"]["steps_used"] == 3


def test_metrics_endpoint_returns_aggregates():
    client = TestClient(app)
    response = client.get("/api/v1/metrics")
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert "requests_total" in body["result"]
    assert "duplicate_tool_calls_total" in body["result"]
    assert "semantic_duplicate_tool_calls_total" in body["result"]
    assert "cached_tool_reuses_total" in body["result"]
    assert "cooldown_skips_total" in body["result"]
    assert "avg_tool_calls_per_run" in body["result"]
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
    assert "avg_tool_calls_per_run" in body["result"]["summary"]
    assert "duplicate_tool_calls_total" in body["result"]["breakdown"]
    assert "semantic_duplicate_tool_calls_total" in body["result"]["breakdown"]
    assert "cached_tool_reuses_total" in body["result"]["breakdown"]
    assert "cooldown_skips_total" in body["result"]["breakdown"]
    assert "recent_runs" in body["result"]
