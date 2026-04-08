"""G1 single-agent runners for the API service layer."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.agents.g1.g1_agent import create_g1_agent
from src.agents.g1.llm_payload import extract_response_text
from src.config.settings import Settings
from src.benchmarking.evaluator import AgentEvaluator
from src.utils.prompt_manager import PromptManager

from .guardrails import (
    apply_action_gating,
    apply_output_policy_guard,
    count_evidence_markers,
    detect_prompt_injection,
    enforce_response_boundaries,
    sanitize_untrusted_text,
    validate_input,
)
from .response_parser import (
    build_structured_g1_report,
    critic_validate_structured_output,
    summarize_text,
)
from .agent_loop_runtime import (
    activate_runtime_budget,
    build_budget_summary,
    build_step_trace,
    create_runtime_budget_state,
    deactivate_runtime_budget,
    normalize_stop_reason,
    resolve_stop_reason,
    sync_runtime_budget_steps,
)
from .schemas import StepTrace

_PROMPT_MANAGER = PromptManager()
_EVALUATOR = AgentEvaluator()

_SAFE_SESSION_ID = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")


def _normalize_session_id(session_id: Optional[str]) -> Optional[str]:
    """Map client session ids to filesystem-safe keys for session persistence."""
    if session_id is None:
        return None
    s = session_id.strip()
    if not s:
        return None
    if _SAFE_SESSION_ID.fullmatch(s):
        return s
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _create_g1_agent_for_session(session_id: Optional[str]):
    """Create a fresh G1 agent with session-specific memory."""
    storage_id = _normalize_session_id(session_id)
    return create_g1_agent(
        session_id=storage_id,
    )


def _resolve_prompt_version(mode: str) -> tuple[str, str]:
    selected = Settings.PROMPT_VERSION_G1 if mode == "g1" else Settings.PROMPT_VERSION_G2
    return selected, _PROMPT_MANAGER.load_prompt(selected)


def _build_prompted_input(prompt_template: str, user_input: str) -> str:
    return f"{prompt_template}\n\nUser input:\n{user_input}\n\nAnalysis:"


def _g1_safety_output(injection_detected: bool) -> str:
    if injection_detected:
        return "Blocked — looks like prompt injection. Send logs or a defensive security question only."
    return "OK — no injection patterns flagged."


def _g1_model_routing_summary(high_risk: bool, selected_model: str) -> str:
    if high_risk:
        return f"Using {selected_model} (stronger model for higher-sensitivity topics)."
    return f"Using {selected_model}."


def _g1_analysis_context_line(prompt_version: str) -> str:
    return f"Answer format: prompts/{prompt_version} · Agent role: prompts/g1/system_prompt.txt"


def _g1_output_review_input(high_risk: bool, evidence_count: int, critic_ok: bool, policy_ok: bool) -> str:
    return (
        f"high_risk={high_risk}, evidence_markers={evidence_count}, "
        f"critic_pass={critic_ok}, policy_pass={policy_ok}"
    )


def _g1_output_review_output(
    critic_ok: bool,
    critic_message: str,
    policy_ok: bool,
) -> str:
    if not policy_ok:
        return "Output policy blocked this answer."
    if not critic_ok:
        return f"Needs more context: {critic_message}"
    return "Structure and policy checks passed."


def _g1_execution_trace_step(stop_reason: str, steps_used: int) -> StepTrace:
    budget = build_budget_summary()
    prompt_preview = (
        f"max_steps={budget['max_steps']}, max_tool_calls={budget['max_tool_calls']}, "
        f"max_runtime_seconds={budget['max_runtime_seconds']}"
    )
    input_summary = (
        f"steps_used={steps_used}, "
        f"tool_calls_used={budget['tool_calls_used']}, "
        f"duplicate_tool_calls={budget['duplicate_tool_calls']}, "
        f"semantic_duplicate_tool_calls={budget['semantic_duplicate_tool_calls']}, "
        f"cached_tool_reuses={budget['cached_tool_reuses']}, "
        f"cooldown_skips={budget['cooldown_skips']}, "
        f"tool_failures={budget['tool_failures']}"
    )
    output_summary = (
        f"{stop_reason} · {steps_used} agent step(s) · {budget['tool_calls_used']} tool call(s)"
    )
    return build_step_trace(
        step="ExecutionSummary",
        what_it_does="Tool usage and how the run finished (limits, stop reason).",
        prompt_preview=prompt_preview,
        input_summary=input_summary,
        output_summary=output_summary,
    )


def _evaluate_response_rubric(response_text: str) -> Dict[str, Any]:
    if not Settings.ENABLE_RUBRIC_EVAL:
        return {"rubric_score": None, "rubric_label": "disabled", "checks": {}}
    return _EVALUATOR.evaluate_rubric(response_text)


def _run_single_agent_loop(
    agent: Any, user_input: str, memory_user_text: str
) -> tuple[str, str, int]:
    """Execute bounded single-agent loop with deterministic stop reasons."""
    response = ""
    steps_used = 0
    stop_reason = "budget_exceeded"

    for step_idx in range(Settings.MAX_AGENT_STEPS):
        if sync_runtime_budget_steps(step_idx) == "budget_exceeded":
            break
        steps_used = step_idx + 1
        response = enforce_response_boundaries(
            extract_response_text(
                agent.invoke(
                    {"input": user_input},
                    memory_user_text=memory_user_text,
                    routing_text=memory_user_text,
                )
            )
        )
        budget_stop_reason = sync_runtime_budget_steps(steps_used)
        stop_reason = resolve_stop_reason("completed", budget_stop_reason)
        break

    return response, stop_reason, steps_used


def _append_budget_note(response: str, stop_reason: str) -> str:
    """Add a deterministic note when a run stops because tool/runtime budget was exhausted."""
    if stop_reason != "budget_exceeded":
        return response
    budget = build_budget_summary()
    if budget["tool_calls_used"] < budget["max_tool_calls"]:
        return response
    note = (
        "\n\nExecution stopped because the tool-call budget was exhausted. "
        "Please narrow the request or provide more focused evidence."
    )
    if note.strip() in response:
        return response
    return enforce_response_boundaries(f"{response}{note}".strip())


def _trace_step(
    *,
    step: str,
    what_it_does: str,
    prompt_preview: str,
    input_summary: str,
    output_summary: str,
) -> StepTrace:
    """Small wrapper so all G1 traces are emitted in one consistent shape."""
    return build_step_trace(
        step=step,
        what_it_does=what_it_does,
        prompt_preview=prompt_preview,
        input_summary=input_summary,
        output_summary=output_summary,
    )


def _run_g1_analysis_core(
    user_input: str,
    session_id: Optional[str] = None,
) -> Tuple[str, List[StepTrace], str, str, int, str, Optional[float], str]:
    """Run G1 once and return response plus canonical user-facing trace steps."""
    clean_input = sanitize_untrusted_text(validate_input(user_input, "input"))
    prompt_version, prompt_template = _resolve_prompt_version("g1")
    prompted_input = _build_prompted_input(prompt_template, clean_input)
    high_risk = Settings.is_high_risk_task(clean_input)
    selected_model = Settings.STRONG_MODEL_NAME if Settings.should_use_strong_model(clean_input) else Settings.FAST_MODEL_NAME
    injection_detected = detect_prompt_injection(clean_input)

    trace: List[StepTrace] = [
        _trace_step(
            step="SafetyCheck",
            what_it_does="Checks your message for prompt-injection patterns before calling the model.",
            prompt_preview="",
            input_summary=summarize_text(clean_input),
            output_summary=_g1_safety_output(injection_detected),
        ),
    ]

    if injection_detected:
        return (
            "Potential prompt-injection content detected. Please remove control-instruction text and retry with only incident data.",
            trace,
            selected_model,
            "needs_human",
            0,
            prompt_version,
            None,
            "n/a",
        )

    trace.append(
        _trace_step(
            step="ModelRouting",
            what_it_does="Picks the OpenAI model for this request (faster vs stronger).",
            prompt_preview="",
            input_summary=summarize_text(clean_input),
            output_summary=_g1_model_routing_summary(high_risk, selected_model),
        )
    )

    agent = _create_g1_agent_for_session(session_id)
    budget_state = create_runtime_budget_state(
        max_steps=Settings.MAX_AGENT_STEPS,
        max_tool_calls=Settings.MAX_TOOL_CALLS,
        max_runtime_seconds=Settings.MAX_RUNTIME_SECONDS,
    )
    budget_token = activate_runtime_budget(budget_state)
    execution_summary_step: Optional[StepTrace] = None
    try:
        response, stop_reason, steps_used = _run_single_agent_loop(
            agent, prompted_input, clean_input
        )
        stop_reason = normalize_stop_reason(stop_reason, default="completed")
        stop_reason = resolve_stop_reason(stop_reason, budget_state.stop_reason)
        response = _append_budget_note(response, stop_reason)
        structured = build_structured_g1_report(response)
        critic_ok, critic_message = critic_validate_structured_output(
            structured, high_risk=high_risk, user_text=clean_input
        )
        if not critic_ok:
            response = enforce_response_boundaries(
                f"{response}\n\nCritic verdict: {critic_message} Please provide more logs, IOC context, or CTI evidence."
            )
            stop_reason = resolve_stop_reason(stop_reason, "needs_human")
        evidence_count = count_evidence_markers(response)
        response, gated_stop_reason = apply_action_gating(response, high_risk=high_risk, evidence_count=evidence_count)
        stop_reason = resolve_stop_reason(stop_reason, gated_stop_reason)
        policy_ok, _ = apply_output_policy_guard(response)
        if not policy_ok:
            response = (
                "Output policy blocked this response due to potentially unsafe content. "
                "Please narrow the request to defensive security analysis."
            )
            stop_reason = resolve_stop_reason(stop_reason, "needs_human")
        execution_summary_step = _g1_execution_trace_step(stop_reason, steps_used)
    finally:
        deactivate_runtime_budget(budget_token)

    if execution_summary_step is None:
        raise RuntimeError("G1 execution summary step missing after successful run")
    trace += [
        _trace_step(
            step="Analysis",
            what_it_does="Runs the tool-enabled agent (log parser, threat intel, optional knowledge search).",
            prompt_preview=_g1_analysis_context_line(prompt_version),
            input_summary=summarize_text(clean_input, 320),
            output_summary=summarize_text(response, 400),
        ),
        _trace_step(
            step="OutputReview",
            what_it_does="Validates structure, evidence, and safety policy on the draft answer.",
            prompt_preview="",
            input_summary=_g1_output_review_input(high_risk, evidence_count, critic_ok, policy_ok),
            output_summary=_g1_output_review_output(critic_ok, critic_message, policy_ok),
        ),
        execution_summary_step,
    ]
    rubric = _evaluate_response_rubric(response)
    return (
        response,
        trace,
        selected_model,
        stop_reason,
        steps_used,
        prompt_version,
        rubric.get("rubric_score"),
        str(rubric.get("rubric_label", "n/a")),
    )


def run_g1_analysis(
    user_input: str,
    session_id: Optional[str] = None,
) -> Tuple[str, List[StepTrace], str, str, int, str, Optional[float], str]:
    """Run G1 analysis and return (response, trace, model, stop_reason, steps, prompt_ver, rubric_score, rubric_label)."""
    return _run_g1_analysis_core(user_input, session_id=session_id)


def run_g1_analysis_with_progress(
    user_input: str,
    on_step: Callable[[StepTrace], None],
    session_id: Optional[str] = None,
) -> Tuple[str, str, str, int, str, Optional[float], str]:
    """Run G1 analysis, emitting each step immediately via on_step callback."""
    response, trace, selected_model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label = _run_g1_analysis_core(
        user_input,
        session_id=session_id,
    )
    for step in trace:
        on_step(step)
    return (response, selected_model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label)


def run_chat(user_input: str, mode: str = "g1", session_id: Optional[str] = None):
    """Run chat in the requested mode (g1 or g2) with shape-aligned output."""
    from .g2_service import run_g2_analysis

    clean_input = validate_input(user_input, "input")
    if mode == "g2":
        result, trace, model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label = run_g2_analysis(
            clean_input, session_id=session_id
        )
        return (result.get("final_report", ""), trace, model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label)
    return run_g1_analysis(clean_input, session_id=session_id)


def run_workspace_with_progress(
    *,
    task: str,
    mode: str,
    user_input: str,
    on_step: Callable[[StepTrace], None],
    session_id: Optional[str] = None,
) -> Tuple[str, str, str, int, str, Optional[float], str]:
    """Run workspace request and emit progress steps for UI streaming."""
    from .g2_service import run_g2_analysis_with_progress

    clean_input = validate_input(user_input, "input")
    if (mode or "g1").lower() == "g2":
        result, model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label = run_g2_analysis_with_progress(
            clean_input, on_step=on_step, session_id=session_id
        )
        return (str(result.get("final_report", "")), model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label)
    return run_g1_analysis_with_progress(clean_input, on_step=on_step, session_id=session_id)
