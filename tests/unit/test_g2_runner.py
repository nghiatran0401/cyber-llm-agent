"""Unit tests for G2 runner nodes and workflow."""

import pytest

from src.config.settings import Settings
from src.agents.g2.state import create_initial_state
from src.agents.g2.nodes import (
    log_analyzer_node,
    threat_predictor_node,
    incident_responder_node,
    orchestrator_node,
)
from src.agents.g2.runner import run_multiagent_with_trace


class _FakeResponse:
    def __init__(self, content: str):
        self.content = content


class _FakeLLM:
    def __init__(self):
        self.prompts = []

    def invoke(self, prompt: str):
        self.prompts.append(prompt)
        lower = prompt.lower()
        if "input logs" in lower:
            return _FakeResponse("Analysis: brute force indicators found.")
        if "predict likely attacker" in lower:
            return _FakeResponse("Prediction: attacker may continue credential stuffing.")
        if "response requirements" in lower or "immediate response" in lower:
            return _FakeResponse("Response: block source IP and reset credentials.")
        if "strict incident response verifier" in lower:
            return _FakeResponse("VERDICT: PASS\nREASON: Supported by evidence.\nFIX: n/a")
        return _FakeResponse("Final: high-risk incident with immediate containment required.")


def test_g2_runner_nodes_update_state_sequentially():
    llm = _FakeLLM()
    state = create_initial_state("Failed login repeated from same host.")
    state = log_analyzer_node(state, llm)
    state = threat_predictor_node(state, llm)
    state = incident_responder_node(state, llm)
    state = orchestrator_node(state, llm)

    assert "Analysis:" in state["log_analysis"]
    assert "Prediction:" in state["threat_prediction"]
    assert "Response:" in state["incident_response"]
    assert "Final:" in state["final_report"]


def test_log_analyzer_rejects_empty_logs():
    llm = _FakeLLM()
    state = create_initial_state("")
    with pytest.raises(ValueError):
        log_analyzer_node(state, llm)


def test_run_multiagent_with_trace_returns_canonical_multi_step_trace():
    llm = _FakeLLM()
    traced = run_multiagent_with_trace("Failed login and scan patterns detected.", llm=llm)

    assert "result" in traced
    assert "trace" in traced
    assert "stop_reason" in traced
    assert "steps_used" in traced
    assert len(traced["trace"]) >= 7
    assert traced["trace"][0]["step"] == "LogAnalyzer"
    assert traced["trace"][-1]["step"] == "Orchestrator"
    assert any(step["step"] == "WorkerPlanner" for step in traced["trace"])
    assert any(step["step"] == "WorkerTask" for step in traced["trace"])
    assert any(step["step"] == "Verifier" for step in traced["trace"])
    assert traced["stop_reason"] == "completed"
    assert traced["steps_used"] == len(traced["trace"])
    # P0 trace integrity: each emitted step should include required trace fields.
    for item in traced["trace"]:
        assert item["step"]
        assert item["what_it_does"]
        assert "prompt_preview" in item
        assert "input_summary" in item
        assert "output_summary" in item


def test_run_multiagent_with_trace_matches_canonical_sequence(monkeypatch):
    """Worker plan length must stay deterministic: live CTI/RAG text can add extra planner keywords."""
    llm = _FakeLLM()
    monkeypatch.setattr(Settings, "OTX_API_KEY", "")
    monkeypatch.setattr(Settings, "ENABLE_RAG", False)
    traced = run_multiagent_with_trace("Failed login and scan patterns detected.", llm=llm)

    assert [item["step"] for item in traced["trace"]] == [
        "LogAnalyzer",
        "WorkerPlanner",
        "ThreatPredictor",
        "WorkerTask",
        "WorkerTask",
        "WorkerTask",
        "IncidentResponder",
        "Verifier",
        "Orchestrator",
    ]


def test_run_multiagent_with_trace_stops_when_step_budget_exceeded(monkeypatch):
    llm = _FakeLLM()
    monkeypatch.setattr("src.agents.g2.runner.Settings.MAX_AGENT_STEPS", 2)
    traced = run_multiagent_with_trace("Failed login and scan patterns detected.", llm=llm)

    assert traced["stop_reason"] == "budget_exceeded"
    assert traced["steps_used"] == 2
    assert len(traced["trace"]) == 2


def test_run_multiagent_with_trace_stops_when_tool_budget_exceeded(monkeypatch):
    llm = _FakeLLM()
    monkeypatch.setattr("src.agents.g2.runner.Settings.MAX_AGENT_STEPS", 12)
    monkeypatch.setattr("src.agents.g2.runner.Settings.MAX_TOOL_CALLS", 1)
    monkeypatch.setattr("src.agents.g2.nodes.Settings.ENABLE_RAG", False)
    monkeypatch.setattr("src.agents.g2.nodes.Settings.OTX_API_KEY", "configured")
    monkeypatch.setattr("src.agents.g2.nodes.parse_system_log", lambda _path: "parsed log evidence")
    monkeypatch.setattr("src.agents.g2.nodes.fetch_cti_intelligence", lambda _query: "live cti evidence")

    traced = run_multiagent_with_trace("incident.log", llm=llm)

    assert traced["stop_reason"] == "budget_exceeded"
    assert traced["steps_used"] >= 1
    assert "runtime_budget" in traced["result"]
    assert traced["result"]["runtime_budget"]["tool_calls_used"] == 1
    assert traced["result"]["runtime_budget"]["tool_failures"] == 0
    assert "ThreatPredictor" in [step["step"] for step in traced["trace"]]


def test_threat_predictor_reuses_existing_cti_evidence(monkeypatch):
    llm = _FakeLLM()
    state = create_initial_state("Failed login repeated from same host.")
    state["log_analysis"] = "Analysis: ransomware activity suspected."
    state["rag_context"] = "Retrieved context already available."
    state["cti_evidence"] = "Cached CTI evidence for ransomware family."
    monkeypatch.setattr("src.agents.g2.nodes.Settings.OTX_API_KEY", "configured")
    monkeypatch.setattr(
        "src.agents.g2.nodes.fetch_cti_intelligence",
        lambda _query: (_ for _ in ()).throw(AssertionError("CTI should have been reused instead of called again")),
    )

    updated = threat_predictor_node(state, llm)

    assert updated["cti_evidence"] == "Cached CTI evidence for ransomware family."

