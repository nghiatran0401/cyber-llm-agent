"""Application service layer for API endpoints."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

from src.agents.g1.agent_with_memory import create_agent_with_memory
from src.agents.g2.multiagent_system import run_multiagent_with_trace
from src.config.settings import Settings
from src.sandbox.owasp_sandbox import append_event_to_live_log, event_to_analysis_text, generate_event, list_scenarios

from .schemas import StepTrace

MAX_INPUT_CHARS = 50_000
_AGENT_CACHE: Dict[str, Any] = {}


def _summarize_text(text: str, max_len: int = 220) -> str:
    content = (text or "").strip().replace("\n", " ")
    if len(content) <= max_len:
        return content
    return content[:max_len] + "..."


def _validate_input(text: str, input_name: str = "input") -> str:
    value = (text or "").strip()
    if not value:
        raise ValueError(f"{input_name} is empty.")
    if len(value) > MAX_INPUT_CHARS:
        raise ValueError(
            f"{input_name} is too large ({len(value)} chars). "
            f"Please keep it under {MAX_INPUT_CHARS} characters."
        )
    return value


def _extract_response_text(result: Any) -> str:
    if isinstance(result, dict):
        if "output" in result:
            return str(result["output"])
        if "messages" in result and result["messages"]:
            last = result["messages"][-1]
            if hasattr(last, "content"):
                return str(last.content)
            if isinstance(last, tuple) and len(last) == 2:
                return str(last[1])
            return str(last)
    if hasattr(result, "content"):
        return str(result.content)
    return str(result)


def _get_or_create_memory_agent(session_id: Optional[str]):
    cache_key = session_id or "__default__"
    if cache_key not in _AGENT_CACHE:
        _AGENT_CACHE[cache_key] = create_agent_with_memory(
            memory_type="buffer",
            max_messages=12,
            session_id=session_id,
            verbose=False,
        )
    return _AGENT_CACHE[cache_key]


def run_g1_analysis(user_input: str, session_id: Optional[str] = None) -> Tuple[str, List[StepTrace], str]:
    """Run G1 analysis and return response text, trace, and selected model."""
    clean_input = _validate_input(user_input, "input")
    strong = Settings.should_use_strong_model(clean_input)
    high_risk = Settings.is_high_risk_task(clean_input)
    selected_model = Settings.STRONG_MODEL_NAME if strong else Settings.FAST_MODEL_NAME

    trace: List[StepTrace] = [
        StepTrace(
            step="InputPreparation",
            what_it_does="Validates and prepares request for G1 execution.",
            prompt_preview=_summarize_text(clean_input),
            input_summary=_summarize_text(clean_input),
            output_summary="Input accepted and formatted.",
        ),
        StepTrace(
            step="RoutingPolicy",
            what_it_does="Chooses fast or strong model and evidence policy.",
            prompt_preview=_summarize_text(
                f"routing=auto strong={strong} high_risk={high_risk} model={selected_model}"
            ),
            input_summary=f"strong={strong}, high_risk={high_risk}",
            output_summary=f"Selected model: {selected_model}",
        ),
    ]

    agent = _get_or_create_memory_agent(session_id)
    response = agent.run(clean_input)
    trace.append(
        StepTrace(
            step="SingleAgentExecution",
            what_it_does="Runs a memory-enabled agent with tools.",
            prompt_preview=_summarize_text(clean_input),
            input_summary=_summarize_text(clean_input),
            output_summary=_summarize_text(response),
        )
    )
    return response, trace, selected_model


def run_g2_analysis(log_input: str) -> Tuple[Dict[str, Any], List[StepTrace], str]:
    """Run G2 workflow and return full structured result, trace, and model."""
    clean_logs = _validate_input(log_input, "input")
    executed = run_multiagent_with_trace(clean_logs)
    result = executed["result"]
    trace = [StepTrace(**step) for step in executed["trace"]]
    return result, trace, Settings.FAST_MODEL_NAME


def run_chat(user_input: str, mode: str = "g1", session_id: Optional[str] = None):
    """Run chat in requested mode with shape-aligned output."""
    clean_input = _validate_input(user_input, "input")
    if mode == "g2":
        result, trace, model = run_g2_analysis(clean_input)
        return result.get("final_report", ""), trace, model
    response, trace, model = run_g1_analysis(clean_input, session_id=session_id)
    return response, trace, model


def simulate_sandbox_event(
    scenario: str,
    vulnerable_mode: bool = False,
    source_ip: str = "127.0.0.1",
    append_to_log: bool = True,
) -> Dict[str, Any]:
    """Generate one sandbox event and optionally append to live log."""
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
    session_id: Optional[str] = None,
):
    """Analyze a structured sandbox event using G1 or G2 flow."""
    event_text = event_to_analysis_text(event)
    if mode == "g2":
        return run_g2_analysis(event_text)
    prompt = f"Analyze this sandbox security event and recommend actions:\n{event_text}"
    return run_g1_analysis(prompt, session_id=session_id)


def get_sandbox_scenarios() -> List[str]:
    """Return supported sandbox scenario keys."""
    return list_scenarios()


def now_ms() -> float:
    return time.perf_counter() * 1000
