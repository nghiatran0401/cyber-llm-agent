"""Compatibility wrapper for relocated G1 memory-enabled agent module."""

from src.agents.g1.agent_with_memory import StatefulSecurityAgent, create_agent_with_memory

__all__ = ["StatefulSecurityAgent", "create_agent_with_memory"]
