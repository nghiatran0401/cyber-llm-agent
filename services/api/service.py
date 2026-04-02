"""
service.py — re-export shim for backward compatibility.

The service layer has been split into dedicated modules:
  - services/api/guardrails.py        → Input/output security guardrails
  - services/api/response_parser.py   → Structured report building
  - services/api/g1_service.py        → G1 single-agent runners
  - services/api/g2_service.py        → G2 multi-agent runners
  - services/api/sandbox_service.py   → Sandbox event simulation/analysis

Import directly from those files for new code.
"""

from .g1_service import (
    run_chat,
    run_g1_analysis,
    run_g1_analysis_with_progress,
    run_workspace_with_progress,
)
from .g2_service import run_g2_analysis, run_g2_analysis_with_progress
from .sandbox_service import analyze_sandbox_event, get_sandbox_scenarios, simulate_sandbox_event

__all__ = [
    "run_g1_analysis",
    "run_g1_analysis_with_progress",
    "run_g2_analysis",
    "run_g2_analysis_with_progress",
    "run_chat",
    "run_workspace_with_progress",
    "simulate_sandbox_event",
    "analyze_sandbox_event",
    "get_sandbox_scenarios",
]
