"""
Purpose: Shared agent utilities reused across generations
What it does:
- Re-exports semantic intent routing helpers
"""

from src.agents.shared.intent_routing import is_high_risk_intent

__all__ = ["is_high_risk_intent"]
