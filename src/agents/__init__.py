"""
Purpose: Package-level exports for cybersecurity agents
What it does:
- Re-exports G1 single-agent implementations
- Re-exports G2 multiagent workflow entry points
- Provides a unified import surface for agent consumers
"""
from src.agents.g1.base_agent import CyberSecurityAgent
from src.agents.g1.agent_with_memory import create_agent_with_memory, StatefulSecurityAgent
from src.agents.g2.multiagent_system import create_multiagent_workflow, run_multiagent_assessment
from src.agents.g1.adaptive_agent import create_simple_agent, AdaptiveSecurityAgent

__all__ = [
    "CyberSecurityAgent",
    "create_simple_agent",
    "AdaptiveSecurityAgent",
    "create_agent_with_memory",
    "StatefulSecurityAgent",
    "create_multiagent_workflow",
    "run_multiagent_assessment",
]

