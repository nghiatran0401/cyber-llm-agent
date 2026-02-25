"""
multiagent_system.py — re-export shim for backward compatibility.

The multiagent system has been split into dedicated modules:
  - src/agents/g2/state.py   → AgentState, MultiagentStepTrace, create_initial_state
  - src/agents/g2/nodes.py   → Individual agent node functions
  - src/agents/g2/graph.py   → LangGraph workflow builder
  - src/agents/g2/runner.py  → Public runner functions

Import directly from those files for new code.
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
