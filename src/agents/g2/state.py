"""
Purpose: Shared state contracts for G2 workflow execution
What it does:
- Defines typed dictionaries for workflow state and step traces
- Encodes required fields passed across all multiagent nodes
- Provides an initializer for default state values
"""

from __future__ import annotations

from typing import Dict, List, TypedDict


class AgentState(TypedDict):
    """State shared across multiagent nodes."""

    logs: str
    log_evidence: str
    rag_context: str
    cti_evidence: str
    worker_plan: List[str]
    worker_reports: Dict[str, str]
    verifier_feedback: str
    verifier_passed: bool
    log_analysis: str
    threat_prediction: str
    incident_response: str
    final_report: str


class MultiagentStepTrace(TypedDict):
    """Human-readable trace for one multiagent node execution."""

    step: str
    what_it_does: str
    prompt_preview: str
    input_summary: str
    output_summary: str


def create_initial_state(logs: str) -> AgentState:
    """Create default state for a new multiagent run."""
    return {
        "logs": logs,
        "log_evidence": "",
        "rag_context": "",
        "cti_evidence": "",
        "worker_plan": [],
        "worker_reports": {},
        "verifier_feedback": "",
        "verifier_passed": False,
        "log_analysis": "",
        "threat_prediction": "",
        "incident_response": "",
        "final_report": "",
    }
