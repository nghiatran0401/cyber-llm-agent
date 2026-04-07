"""G2 multi-agent runners for the API service layer."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

from src.agents.g2.runner import run_multiagent_with_trace
from src.config.settings import Settings
from src.benchmarking.evaluator import AgentEvaluator
from src.utils.prompt_manager import PromptManager

from .guardrails import (
    apply_action_gating,
    apply_output_policy_guard,
    count_evidence_markers,
    detect_prompt_injection,
    sanitize_untrusted_text,
    validate_input,
)
from .agent_loop_runtime import build_step_trace, normalize_stop_reason, resolve_stop_reason
from .response_parser import summarize_text
from .schemas import StepTrace

_PROMPT_MANAGER = PromptManager()
_EVALUATOR = AgentEvaluator()


def _resolve_prompt_version() -> tuple[str, str]:
    selected = Settings.PROMPT_VERSION_G2
    return selected, _PROMPT_MANAGER.load_prompt(selected)


def _build_prompted_input(prompt_template: str, user_input: str) -> str:
    return f"{prompt_template}\n\nUser input:\n{user_input}\n\nAnalysis:"


def _evaluate_response_rubric(response_text: str) -> Dict[str, Any]:
    if not Settings.ENABLE_RUBRIC_EVAL:
        return {"rubric_score": None, "rubric_label": "disabled", "checks": {}}
    return _EVALUATOR.evaluate_rubric(response_text)


def _g2_safety_output(injection_detected: bool) -> str:
    if injection_detected:
        return "Blocked - looks like prompt injection. Send logs or a defensive security question only."
    return "OK - no injection patterns flagged."


def _g2_output_review_input(high_risk: bool, evidence_count: int, policy_ok: bool) -> str:
    return (
        f"high_risk={high_risk}, evidence_markers={evidence_count}, "
        f"policy_pass={policy_ok}"
    )


def _g2_analysis_output_summary(executed_steps: List[Dict[str, str]], final_report: str) -> str:
    step_names = [str(item.get("step", "Unknown")) for item in executed_steps]
    compact_steps = " -> ".join(step_names)
    return summarize_text(f"Flow: {compact_steps}\nFinal report: {final_report}", 400)


def _fallback_final_report_from_state(
    result: Dict[str, Any],
    *,
    stop_reason: str,
) -> str:
    """Build a deterministic report when orchestrator output is empty."""
    log_analysis = summarize_text(str(result.get("log_analysis", "")).strip(), 900) or "No log analysis available."
    threat_prediction = (
        summarize_text(str(result.get("threat_prediction", "")).strip(), 900) or "No threat prediction available."
    )
    incident_response = (
        summarize_text(str(result.get("incident_response", "")).strip(), 1200) or "No containment actions available."
    )
    worker_reports = result.get("worker_reports", {})
    worker_count = len(worker_reports) if isinstance(worker_reports, dict) else 0
    runtime_budget = result.get("runtime_budget", {})
    steps_used = runtime_budget.get("steps_used", "unknown")
    tool_calls_used = runtime_budget.get("tool_calls_used", 0)
    return (
        "### Executive Summary\n\n"
        "Automated G2 analysis completed, but the final synthesis step returned empty output. "
        "This fallback summarizes the strongest available evidence so you can proceed safely.\n\n"
        f"- **Run status:** {stop_reason}\n"
        f"- **Execution budget:** steps_used={steps_used}, tool_calls_used={tool_calls_used}, worker_reports={worker_count}\n\n"
        "### Log Analysis\n"
        f"{log_analysis}\n\n"
        "### Likely Threat Progression\n"
        f"{threat_prediction}\n\n"
        "### Immediate Actions\n"
        f"{incident_response}"
    )


def _g2_execution_trace_step(
    runtime_budget: Dict[str, Any],
    stop_reason: str,
    steps_used: int,
) -> StepTrace:
    prompt_preview = (
        f"max_steps={runtime_budget.get('max_steps', Settings.MAX_AGENT_STEPS)}, "
        f"max_tool_calls={runtime_budget.get('max_tool_calls', Settings.MAX_TOOL_CALLS)}, "
        f"max_runtime_seconds={runtime_budget.get('max_runtime_seconds', Settings.MAX_RUNTIME_SECONDS)}"
    )
    input_summary = (
        f"steps_used={steps_used}, "
        f"tool_calls_used={runtime_budget.get('tool_calls_used', 0)}, "
        f"duplicate_tool_calls={runtime_budget.get('duplicate_tool_calls', 0)}, "
        f"semantic_duplicate_tool_calls={runtime_budget.get('semantic_duplicate_tool_calls', 0)}, "
        f"cached_tool_reuses={runtime_budget.get('cached_tool_reuses', 0)}, "
        f"cooldown_skips={runtime_budget.get('cooldown_skips', 0)}, "
        f"tool_failures={runtime_budget.get('tool_failures', 0)}"
    )
    output_summary = (
        f"{stop_reason} - {steps_used} agent step(s) - "
        f"{runtime_budget.get('tool_calls_used', 0)} tool call(s)"
    )
    return _trace_step(
        step="ExecutionSummary",
        what_it_does="Tool usage and how the run finished (limits, stop reason).",
        prompt_preview=prompt_preview,
        input_summary=input_summary,
        output_summary=output_summary,
    )


def _trace_step(
    *,
    step: str,
    what_it_does: str,
    prompt_preview: str,
    input_summary: str,
    output_summary: str,
) -> StepTrace:
    """Shared StepTrace builder for all G2 paths."""
    return build_step_trace(
        step=step,
        what_it_does=what_it_does,
        prompt_preview=prompt_preview,
        input_summary=input_summary,
        output_summary=output_summary,
    )


def _run_g2_analysis_core(
    log_input: str,
) -> Tuple[Dict[str, Any], List[StepTrace], str, str, int, str, Optional[float], str]:
    clean_logs = sanitize_untrusted_text(validate_input(log_input, "input"))
    prompt_version, prompt_template = _resolve_prompt_version()
    prompted_logs = _build_prompted_input(prompt_template, clean_logs)
    injection_detected = detect_prompt_injection(clean_logs)
    initial_steps: List[StepTrace] = [
        _trace_step(
            step="SafetyCheck",
            what_it_does="Checks your message for prompt-injection patterns before calling the model.",
            prompt_preview="",
            input_summary=summarize_text(clean_logs),
            output_summary=_g2_safety_output(injection_detected),
        ),
    ]
    if injection_detected:
        return (
            {"final_report": "Potential prompt-injection content detected. Provide only incident evidence."},
            initial_steps,
            Settings.FAST_MODEL_NAME,
            "needs_human",
            0,
            prompt_version,
            None,
            "n/a",
        )

    initial_steps.append(
        _trace_step(
            step="ModelRouting",
            what_it_does="Picks the OpenAI model for this request (faster vs stronger).",
            prompt_preview="",
            input_summary=summarize_text(clean_logs),
            output_summary=f"Using {Settings.FAST_MODEL_NAME}.",
        )
    )

    executed = run_multiagent_with_trace(prompted_logs)
    result = executed["result"]
    runtime_budget = dict(result.get("runtime_budget", {})) if isinstance(result, dict) else {}
    stop_reason = normalize_stop_reason(str(executed.get("stop_reason", "completed")), default="completed")
    steps_used = int(executed.get("steps_used", len(executed.get("trace", []))))
    final_text = str(result.get("final_report", ""))
    if not final_text.strip():
        result["final_report"] = _fallback_final_report_from_state(result, stop_reason=stop_reason)
        final_text = result["final_report"]
    high_risk = Settings.is_high_risk_task(clean_logs)
    evidence_count = count_evidence_markers(final_text + "\n" + str(result.get("cti_evidence", "")))
    gated_text, gated_stop_reason = apply_action_gating(final_text, high_risk=high_risk, evidence_count=evidence_count)
    result["final_report"] = gated_text
    stop_reason = resolve_stop_reason(stop_reason, gated_stop_reason)
    policy_ok, _ = apply_output_policy_guard(result["final_report"])
    if not policy_ok:
        result["final_report"] = "Output policy blocked this response due to potentially unsafe content. Please narrow the request to defensive security analysis."
        stop_reason = resolve_stop_reason(stop_reason, "needs_human")
    rubric = _evaluate_response_rubric(result["final_report"])

    final_steps: List[StepTrace] = [
        _trace_step(
            step="Analysis",
            what_it_does="Runs the multi-agent workflow (log analysis, threat prediction, workers, response, verification).",
            prompt_preview=f"Answer format: prompts/{prompt_version} · Multi-agent role set: g2",
            input_summary=summarize_text(clean_logs, 320),
            output_summary=_g2_analysis_output_summary(executed.get("trace", []), result["final_report"]),
        ),
        _trace_step(
            step="OutputReview",
            what_it_does="Validates evidence coverage and safety policy on the draft answer.",
            prompt_preview=f"min_evidence={Settings.MIN_EVIDENCE_FOR_HIGH_RISK}",
            input_summary=_g2_output_review_input(high_risk, evidence_count, policy_ok),
            output_summary=(
                "Evidence and safety checks passed."
                if policy_ok
                else "Output policy blocked this answer."
            ),
        ),
        _g2_execution_trace_step(runtime_budget, stop_reason, steps_used),
    ]

    return (
        result,
        initial_steps + final_steps,
        Settings.FAST_MODEL_NAME,
        stop_reason,
        steps_used,
        prompt_version,
        rubric.get("rubric_score"),
        str(rubric.get("rubric_label", "n/a")),
    )


def run_g2_analysis(
    log_input: str,
) -> Tuple[Dict[str, Any], List[StepTrace], str, str, int, str, Optional[float], str]:
    """Run G2 multi-agent workflow. Returns (result, trace, model, stop_reason, steps, prompt_ver, rubric_score, rubric_label)."""
    return _run_g2_analysis_core(log_input)


def run_g2_analysis_with_progress(
    log_input: str,
    on_step: Callable[[StepTrace], None],
) -> Tuple[Dict[str, Any], str, str, int, str, Optional[float], str]:
    """Run G2 analysis, emitting each step immediately via on_step callback."""
    result, trace, model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label = _run_g2_analysis_core(log_input)
    for step in trace:
        on_step(step)
    return (result, model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label)
