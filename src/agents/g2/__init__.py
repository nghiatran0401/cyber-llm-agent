"""
Purpose: Exports for G2 multiagent workflow modules
What it does:
- Re-exports role configuration and registry objects
- Re-exports shared state and trace type definitions
- Re-exports workflow builders and runner entry points
"""

from src.agents.g2.multiagent_config import (
    AgentRole,
    LOG_ANALYZER_ROLE,
    THREAT_PREDICTOR_ROLE,
    INCIDENT_RESPONDER_ROLE,
    ORCHESTRATOR_ROLE,
    ROLE_REGISTRY,
)
from src.agents.g2.multiagent_system import (
    AgentState,
    MultiagentStepTrace,
    create_initial_state,
    create_multiagent_workflow,
    run_multiagent_assessment,
    run_multiagent_with_trace,
)

__all__ = [
    "AgentRole",
    "LOG_ANALYZER_ROLE",
    "THREAT_PREDICTOR_ROLE",
    "INCIDENT_RESPONDER_ROLE",
    "ORCHESTRATOR_ROLE",
    "ROLE_REGISTRY",
    "AgentState",
    "MultiagentStepTrace",
    "create_initial_state",
    "create_multiagent_workflow",
    "run_multiagent_assessment",
    "run_multiagent_with_trace",
]
