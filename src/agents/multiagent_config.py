"""Compatibility wrapper for relocated G2 role configuration module."""

from src.agents.g2.multiagent_config import (
    AgentRole,
    LOG_ANALYZER_ROLE,
    THREAT_PREDICTOR_ROLE,
    INCIDENT_RESPONDER_ROLE,
    ORCHESTRATOR_ROLE,
    ROLE_REGISTRY,
)

__all__ = [
    "AgentRole",
    "LOG_ANALYZER_ROLE",
    "THREAT_PREDICTOR_ROLE",
    "INCIDENT_RESPONDER_ROLE",
    "ORCHESTRATOR_ROLE",
    "ROLE_REGISTRY",
]
