"""Role definitions for the Week 6 multiagent system."""

from dataclasses import dataclass
from typing import Dict, List


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
    system_prompt=(
        "You are a security log analyst.\n"
        "Tasks:\n"
        "1. Parse and analyze system logs\n"
        "2. Identify suspicious patterns (failed logins, scans, unauthorized access)\n"
        "3. Classify severity\n"
        "4. Return concise findings for downstream agents"
    ),
    tools=["LogParser"],
)

THREAT_PREDICTOR_ROLE = AgentRole(
    name="ThreatPredictor",
    description="Predicts likely next attack steps from observed indicators.",
    system_prompt=(
        "You are a threat intelligence analyst.\n"
        "Tasks:\n"
        "1. Infer likely attack progression from current evidence\n"
        "2. Assess risk level\n"
        "3. Highlight probable next moves by attacker"
    ),
    tools=["CTIFetch"],
)

INCIDENT_RESPONDER_ROLE = AgentRole(
    name="IncidentResponder",
    description="Converts predictions into practical containment and recovery steps.",
    system_prompt=(
        "You are an incident response coordinator.\n"
        "Tasks:\n"
        "1. Prioritize remediation actions\n"
        "2. Recommend immediate containment steps\n"
        "3. Suggest short follow-up actions and monitoring checks"
    ),
    tools=["CTIFetch"],
)

ORCHESTRATOR_ROLE = AgentRole(
    name="Orchestrator",
    description="Synthesizes all agent outputs into one executive-ready report.",
    system_prompt=(
        "You are the SOC orchestrator.\n"
        "Tasks:\n"
        "1. Consolidate analyst outputs\n"
        "2. Present a clear final summary\n"
        "3. Include confidence and priority actions"
    ),
    tools=["all_agents"],
)


ROLE_REGISTRY: Dict[str, AgentRole] = {
    LOG_ANALYZER_ROLE.name: LOG_ANALYZER_ROLE,
    THREAT_PREDICTOR_ROLE.name: THREAT_PREDICTOR_ROLE,
    INCIDENT_RESPONDER_ROLE.name: INCIDENT_RESPONDER_ROLE,
    ORCHESTRATOR_ROLE.name: ORCHESTRATOR_ROLE,
}

