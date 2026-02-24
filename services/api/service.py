"""Application service layer for API endpoints."""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.agents.g1.agent_with_memory import create_agent_with_memory
from src.agents.g2.multiagent_system import run_multiagent_with_trace
from src.config.settings import Settings
from src.sandbox.owasp_sandbox import append_event_to_live_log, event_to_analysis_text, generate_event, list_scenarios

from .schemas import StepTrace

MAX_INPUT_CHARS = 50_000
MAX_EVENT_TEXT_CHARS = 10_000
MAX_EVENT_KEYS = 32
_AGENT_CACHE: Dict[str, tuple[Any, float]] = {}
_HUMAN_NEEDED_SIGNALS = (
    "need more data",
    "please provide",
    "insufficient evidence",
    "cannot determine",
    "unable to determine",
)


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


def _enforce_response_boundaries(text: str, max_chars: int = 12000) -> str:
    content = str(text or "").replace("\x00", "").strip()
    if len(content) <= max_chars:
        return content
    return content[: max_chars - 3].rstrip() + "..."


def _infer_stop_reason(response_text: str) -> str:
    content = (response_text or "").lower()
    if any(signal in content for signal in _HUMAN_NEEDED_SIGNALS):
        return "needs_human"
    if not content.strip():
        return "blocked"
    return "completed"


def _run_single_agent_loop(agent: Any, user_input: str) -> tuple[str, str, int]:
    """Execute bounded single-agent loop with deterministic stop reasons."""
    start_time = time.perf_counter()
    response = ""
    steps_used = 0
    stop_reason = "budget_exceeded"
    current_input = user_input

    for step_idx in range(Settings.MAX_AGENT_STEPS):
        elapsed = time.perf_counter() - start_time
        if elapsed > Settings.MAX_RUNTIME_SECONDS:
            stop_reason = "budget_exceeded"
            break
        steps_used = step_idx + 1
        response = _enforce_response_boundaries(agent.run(current_input))
        stop_reason = _infer_stop_reason(response)
        # Phase 1 loop foundation: one complete step exits deterministically.
        if stop_reason in {"completed", "needs_human", "blocked"}:
            break
        current_input = (
            "Continue the analysis from the latest evidence and provide only net-new findings.\n\n"
            f"Previous response:\n{response}"
        )

    return response, stop_reason, steps_used


def _prune_agent_cache() -> None:
    now = time.time()
    expired = []
    for key, (_, created_at) in _AGENT_CACHE.items():
        if now - created_at > Settings.AGENT_CACHE_TTL_SECONDS:
            expired.append(key)
    for key in expired:
        _AGENT_CACHE.pop(key, None)
    if len(_AGENT_CACHE) > Settings.AGENT_CACHE_MAX_SIZE:
        oldest_key = min(_AGENT_CACHE.items(), key=lambda item: item[1][1])[0]
        _AGENT_CACHE.pop(oldest_key, None)


def _validate_event_payload(event: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError("event must be an object.")
    if len(event) > MAX_EVENT_KEYS:
        raise ValueError(f"event has too many keys (max={MAX_EVENT_KEYS}).")
    serialized = _validate_input(str(event), "event")
    if len(serialized) > MAX_EVENT_TEXT_CHARS:
        raise ValueError(f"event is too large. Keep under {MAX_EVENT_TEXT_CHARS} characters.")
    return event


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
    _prune_agent_cache()
    if cache_key not in _AGENT_CACHE:
        _AGENT_CACHE[cache_key] = (
            create_agent_with_memory(
            memory_type="buffer",
            max_messages=12,
            session_id=session_id,
            verbose=False,
            ),
            time.time(),
        )
    return _AGENT_CACHE[cache_key][0]


def run_g1_analysis(
    user_input: str,
    session_id: Optional[str] = None,
) -> Tuple[str, List[StepTrace], str, str, int]:
    """Run G1 analysis and return response text, trace, model, stop reason, and steps."""
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
    response, stop_reason, steps_used = _run_single_agent_loop(agent, clean_input)
    trace.append(
        StepTrace(
            step="SingleAgentExecution",
            what_it_does="Runs a memory-enabled agent with tools.",
            prompt_preview=_summarize_text(clean_input),
            input_summary=_summarize_text(clean_input),
            output_summary=_summarize_text(response),
        )
    )
    trace.append(
        StepTrace(
            step="RunControl",
            what_it_does="Tracks loop stop condition and bounded execution state.",
            prompt_preview=f"max_steps={Settings.MAX_AGENT_STEPS}, max_runtime_s={Settings.MAX_RUNTIME_SECONDS}",
            input_summary=f"steps_used={steps_used}",
            output_summary=f"stop_reason={stop_reason}",
        )
    )
    return response, trace, selected_model, stop_reason, steps_used


def run_g1_analysis_with_progress(
    user_input: str,
    on_step: Callable[[StepTrace], None],
    session_id: Optional[str] = None,
) -> Tuple[str, str, str, int]:
    """Run G1 with progressive step callbacks."""
    clean_input = _validate_input(user_input, "input")
    strong = Settings.should_use_strong_model(clean_input)
    high_risk = Settings.is_high_risk_task(clean_input)
    selected_model = Settings.STRONG_MODEL_NAME if strong else Settings.FAST_MODEL_NAME

    step1 = StepTrace(
        step="InputPreparation",
        what_it_does="Validates and prepares request for G1 execution.",
        prompt_preview=_summarize_text(clean_input),
        input_summary=_summarize_text(clean_input),
        output_summary="Input accepted and formatted.",
    )
    on_step(step1)

    step2 = StepTrace(
        step="RoutingPolicy",
        what_it_does="Chooses fast or strong model and evidence policy.",
        prompt_preview=_summarize_text(
            f"routing=auto strong={strong} high_risk={high_risk} model={selected_model}"
        ),
        input_summary=f"strong={strong}, high_risk={high_risk}",
        output_summary=f"Selected model: {selected_model}",
    )
    on_step(step2)

    agent = _get_or_create_memory_agent(session_id)
    response, stop_reason, steps_used = _run_single_agent_loop(agent, clean_input)
    step3 = StepTrace(
        step="SingleAgentExecution",
        what_it_does="Runs a memory-enabled agent with tools.",
        prompt_preview=_summarize_text(clean_input),
        input_summary=_summarize_text(clean_input),
        output_summary=_summarize_text(response),
    )
    on_step(step3)
    on_step(
        StepTrace(
            step="RunControl",
            what_it_does="Tracks loop stop condition and bounded execution state.",
            prompt_preview=f"max_steps={Settings.MAX_AGENT_STEPS}, max_runtime_s={Settings.MAX_RUNTIME_SECONDS}",
            input_summary=f"steps_used={steps_used}",
            output_summary=f"stop_reason={stop_reason}",
        )
    )
    return response, selected_model, stop_reason, steps_used


def run_g2_analysis(log_input: str) -> Tuple[Dict[str, Any], List[StepTrace], str, str, int]:
    """Run G2 workflow and return result, trace, model, stop reason, and steps."""
    clean_logs = _validate_input(log_input, "input")
    executed = run_multiagent_with_trace(clean_logs)
    result = executed["result"]
    trace = [StepTrace(**step) for step in executed["trace"]]
    stop_reason = str(executed.get("stop_reason", "completed"))
    steps_used = int(executed.get("steps_used", len(trace)))
    return result, trace, Settings.FAST_MODEL_NAME, stop_reason, steps_used


def run_g2_analysis_with_progress(
    log_input: str,
    on_step: Callable[[StepTrace], None],
) -> Tuple[Dict[str, Any], str, str, int]:
    """Run G2 and emit each step as soon as it completes."""
    clean_logs = _validate_input(log_input, "input")

    def _on_step(step: Dict[str, str]):
        on_step(StepTrace(**step))

    executed = run_multiagent_with_trace(clean_logs, on_step=_on_step)
    stop_reason = str(executed.get("stop_reason", "completed"))
    steps_used = int(executed.get("steps_used", len(executed.get("trace", []))))
    return executed["result"], Settings.FAST_MODEL_NAME, stop_reason, steps_used


def run_chat(user_input: str, mode: str = "g1", session_id: Optional[str] = None):
    """Run chat in requested mode with shape-aligned output."""
    clean_input = _validate_input(user_input, "input")
    if mode == "g2":
        result, trace, model, stop_reason, steps_used = run_g2_analysis(clean_input)
        return result.get("final_report", ""), trace, model, stop_reason, steps_used
    response, trace, model, stop_reason, steps_used = run_g1_analysis(clean_input, session_id=session_id)
    return response, trace, model, stop_reason, steps_used


def run_workspace_with_progress(
    *,
    task: str,
    mode: str,
    user_input: str,
    on_step: Callable[[StepTrace], None],
    session_id: Optional[str] = None,
) -> Tuple[str, str, str, int]:
    """Run workspace request and emit progress steps for UI streaming."""
    clean_input = _validate_input(user_input, "input")
    normalized_task = (task or "chat").lower()
    normalized_mode = (mode or "g1").lower()

    if normalized_mode == "g2":
        result, model, stop_reason, steps_used = run_g2_analysis_with_progress(clean_input, on_step=on_step)
        return str(result.get("final_report", "")), model, stop_reason, steps_used

    if normalized_task == "analyze":
        return run_g1_analysis_with_progress(clean_input, on_step=on_step, session_id=session_id)
    return run_g1_analysis_with_progress(clean_input, on_step=on_step, session_id=session_id)


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
    _validate_event_payload(event)
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
