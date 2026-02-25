"""Sandbox service: generate, log, and analyze OWASP sandbox events."""

from __future__ import annotations

from typing import Any, Dict, List

from src.sandbox.owasp_sandbox import (
    append_event_to_live_log,
    event_to_analysis_text,
    generate_event,
    list_scenarios,
)
from src.utils.prompt_templates import render_prompt_template

from .guardrails import validate_event_payload


def simulate_sandbox_event(
    scenario: str,
    vulnerable_mode: bool = False,
    source_ip: str = "127.0.0.1",
    append_to_log: bool = True,
) -> Dict[str, Any]:
    """Generate one sandbox event and optionally append it to the live log."""
    event = generate_event(
        scenario_key=scenario,
        vulnerable_mode=vulnerable_mode,
        source_ip=source_ip.strip() or "127.0.0.1",
    )
    if append_to_log:
        path = append_event_to_live_log(event)
        event["log_path"] = str(path)
    return event


def analyze_sandbox_event(
    event: Dict[str, Any],
    mode: str = "g1",
    session_id: str | None = None,
):
    """Analyze a structured sandbox event using the G1 or G2 flow.

    Imports from g1_service / g2_service at call time to avoid circular imports.
    """
    from .g1_service import run_g1_analysis
    from .g2_service import run_g2_analysis

    validate_event_payload(event)
    event_text = event_to_analysis_text(event)
    if mode == "g2":
        return run_g2_analysis(event_text)
    prompt = render_prompt_template("service/sandbox_analysis.txt", event_text=event_text)
    return run_g1_analysis(prompt, session_id=session_id)


def get_sandbox_scenarios() -> List[str]:
    """Return supported sandbox scenario keys."""
    return list_scenarios()
