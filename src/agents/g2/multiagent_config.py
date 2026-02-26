"""
Purpose: Role configuration for the G2 multiagent system
What it does:
- Defines the AgentRole data model for specialist agents
- Loads role-specific system prompts from template files
- Registers named roles for lookup by workflow components
"""

from dataclasses import dataclass
from typing import Dict, List
from src.utils.prompt_templates import load_prompt_template


@dataclass(frozen=True)
class AgentRole:
    """Metadata for each specialized multiagent role."""

    name: str
    description: str
    system_prompt: str
    tools: List[str]


LOG_ANALYZER_ROLE = AgentRole(
    name="LogAnalyzer",
    description="Analyzes logs to detect suspicious patterns and severity.",
    system_prompt=load_prompt_template("g2/roles/log_analyzer.txt"),
    tools=["LogParser"],
)

THREAT_PREDICTOR_ROLE = AgentRole(
    name="ThreatPredictor",
    description="Predicts likely next attack steps from observed indicators.",
    system_prompt=load_prompt_template("g2/roles/threat_predictor.txt"),
    tools=["CTIFetch"],
)

INCIDENT_RESPONDER_ROLE = AgentRole(
    name="IncidentResponder",
    description="Converts predictions into practical containment and recovery steps.",
    system_prompt=load_prompt_template("g2/roles/incident_responder.txt"),
    tools=["CTIFetch"],
)

ORCHESTRATOR_ROLE = AgentRole(
    name="Orchestrator",
    description="Synthesizes all agent outputs into one executive-ready report.",
    system_prompt=load_prompt_template("g2/roles/orchestrator.txt"),
    tools=["all_agents"],
)


ROLE_REGISTRY: Dict[str, AgentRole] = {
    LOG_ANALYZER_ROLE.name: LOG_ANALYZER_ROLE,
    THREAT_PREDICTOR_ROLE.name: THREAT_PREDICTOR_ROLE,
    INCIDENT_RESPONDER_ROLE.name: INCIDENT_RESPONDER_ROLE,
    ORCHESTRATOR_ROLE.name: ORCHESTRATOR_ROLE,
}
