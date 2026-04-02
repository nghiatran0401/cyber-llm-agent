"""
Purpose: Backward-compatible re-export shim for G2
What it does:
- Re-exports the split multiagent workflow interfaces
- Preserves legacy import paths for existing callers
- Directs new code to dedicated state, graph, and runner modules
"""

from .graph import create_multiagent_workflow
from .runner import run_multiagent_assessment, run_multiagent_with_trace
from .state import AgentState, MultiagentStepTrace, create_initial_state

__all__ = [
    "AgentState",
    "MultiagentStepTrace",
    "create_initial_state",
    "create_multiagent_workflow",
    "run_multiagent_assessment",
    "run_multiagent_with_trace",
]
