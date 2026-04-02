"""
Purpose: Backward-compatible re-export shim for G2
What it does:
- Re-exports the split multiagent workflow interfaces
- Preserves legacy import paths for existing callers
- Directs new code to dedicated state, graph, and runner modules
"""

from .graph import create_multiagent_workflow
from .nodes import (
    incident_responder_node,
    log_analyzer_node,
    orchestrator_node,
    threat_predictor_node,
)
from .runner import run_multiagent_assessment, run_multiagent_with_trace
from .state import AgentState, MultiagentStepTrace, create_initial_state

__all__ = [
    "AgentState",
    "MultiagentStepTrace",
    "create_initial_state",
    "create_multiagent_workflow",
    "log_analyzer_node",
    "threat_predictor_node",
    "incident_responder_node",
    "orchestrator_node",
    "run_multiagent_assessment",
    "run_multiagent_with_trace",
]
