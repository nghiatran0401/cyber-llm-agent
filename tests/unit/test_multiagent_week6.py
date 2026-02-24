"""Unit tests for Week 6 multiagent nodes and workflow."""

import pytest

from src.agents.g2.multiagent_system import (
    create_initial_state,
    log_analyzer_node,
    threat_predictor_node,
    incident_responder_node,
    orchestrator_node,
    create_multiagent_workflow,
    run_multiagent_with_trace,
)


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
        if "immediate response" in lower:
            return _FakeResponse("Response: block source IP and reset credentials.")
        return _FakeResponse("Final: high-risk incident with immediate containment required.")


def test_multiagent_nodes_update_state_sequentially():
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


def test_create_multiagent_workflow_runs_end_to_end():
    llm = _FakeLLM()
    workflow = create_multiagent_workflow(llm=llm)
    result = workflow.invoke(create_initial_state("Port scan and failed login activity detected."))
    assert result["final_report"]
    assert len(llm.prompts) >= 4


def test_run_multiagent_with_trace_returns_four_steps():
    llm = _FakeLLM()
    traced = run_multiagent_with_trace("Failed login and scan patterns detected.", llm=llm)

    assert "result" in traced
    assert "trace" in traced
    assert "stop_reason" in traced
    assert "steps_used" in traced
    assert len(traced["trace"]) == 4
    assert traced["trace"][0]["step"] == "LogAnalyzer"
    assert traced["trace"][-1]["step"] == "Orchestrator"
    assert traced["stop_reason"] == "completed"
    assert traced["steps_used"] == 4


def test_run_multiagent_with_trace_stops_when_step_budget_exceeded(monkeypatch):
    llm = _FakeLLM()
    monkeypatch.setattr("src.agents.g2.multiagent_system.Settings.MAX_AGENT_STEPS", 2)
    traced = run_multiagent_with_trace("Failed login and scan patterns detected.", llm=llm)

    assert traced["stop_reason"] == "budget_exceeded"
    assert traced["steps_used"] == 2
    assert len(traced["trace"]) == 2

