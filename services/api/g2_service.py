"""G2 multi-agent runners for the API service layer."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

from src.agents.g2.multiagent_system import run_multiagent_with_trace
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


def run_g2_analysis(
    log_input: str,
) -> Tuple[Dict[str, Any], List[StepTrace], str, str, int, str, Optional[float], str]:
    """Run G2 multi-agent workflow. Returns (result, trace, model, stop_reason, steps, prompt_ver, rubric_score, rubric_label)."""
    clean_logs = sanitize_untrusted_text(validate_input(log_input, "input"))
    prompt_version, prompt_template = _resolve_prompt_version()
    prompted_logs = _build_prompted_input(prompt_template, clean_logs)
    injection_detected = Settings.ENABLE_PROMPT_INJECTION_GUARD and detect_prompt_injection(clean_logs)

    if injection_detected:
        trace = [StepTrace(step="SafetyGuard", what_it_does="Detects prompt-injection patterns before execution.",
                           prompt_preview="prompt_injection_guard=enabled", input_summary=summarize_text(clean_logs),
                           output_summary="injection_detected=True")]
        return ({"final_report": "Potential prompt-injection content detected. Provide only incident evidence."},
                trace, Settings.FAST_MODEL_NAME, "needs_human", 0, prompt_version, None, "n/a")

    executed = run_multiagent_with_trace(prompted_logs)
    result = executed["result"]
    trace = [StepTrace(**step) for step in executed["trace"]]
    trace.insert(0, StepTrace(step="PromptVersion", what_it_does="Loads prompt template version for this run.",
                              prompt_preview=summarize_text(prompt_template, 180), input_summary=f"mode=g2 version={prompt_version}",
                              output_summary="Prompt template resolved successfully."))
    stop_reason = str(executed.get("stop_reason", "completed"))
    steps_used = int(executed.get("steps_used", len(trace)))
    final_text = str(result.get("final_report", ""))
    evidence_count = count_evidence_markers(final_text + "\n" + str(result.get("cti_evidence", "")))
    gated_text, gated_stop_reason = apply_action_gating(final_text, high_risk=Settings.is_high_risk_task(clean_logs), evidence_count=evidence_count)
    result["final_report"] = gated_text
    if stop_reason != "error" and gated_stop_reason == "needs_human":
        stop_reason = "needs_human"
    policy_ok, policy_status = apply_output_policy_guard(result["final_report"])
    if not policy_ok:
        result["final_report"] = "Output policy blocked this response due to potentially unsafe content. Please narrow the request to defensive security analysis."
        stop_reason = "needs_human"
    rubric = _evaluate_response_rubric(result["final_report"])
    trace += [
        StepTrace(step="PolicyGuard", what_it_does="Applies output-policy and high-risk action gates.",
                  prompt_preview=f"min_evidence={Settings.MIN_EVIDENCE_FOR_HIGH_RISK}",
                  input_summary=f"evidence_count={evidence_count}",
                  output_summary=f"policy={policy_status}, stop_reason={stop_reason}"),
        StepTrace(step="RubricEvaluation", what_it_does="Scores response quality against rubric checks.",
                  prompt_preview="criteria={evidence,severity,actions,clarity}", input_summary=summarize_text(final_text),
                  output_summary=f"score={rubric.get('rubric_score')} label={rubric.get('rubric_label')}"),
    ]
    return (result, trace, Settings.FAST_MODEL_NAME, stop_reason, steps_used, prompt_version, rubric.get("rubric_score"), str(rubric.get("rubric_label", "n/a")))


def run_g2_analysis_with_progress(
    log_input: str,
    on_step: Callable[[StepTrace], None],
) -> Tuple[Dict[str, Any], str, str, int, str, Optional[float], str]:
    """Run G2 analysis, emitting each step immediately via on_step callback."""
    clean_logs = sanitize_untrusted_text(validate_input(log_input, "input"))
    prompt_version, prompt_template = _resolve_prompt_version()
    prompted_logs = _build_prompted_input(prompt_template, clean_logs)
    injection_detected = Settings.ENABLE_PROMPT_INJECTION_GUARD and detect_prompt_injection(clean_logs)

    if injection_detected:
        on_step(StepTrace(step="SafetyGuard", what_it_does="Detects prompt-injection patterns.",
                          prompt_preview="prompt_injection_guard=enabled", input_summary=summarize_text(clean_logs),
                          output_summary="injection_detected=True"))
        return ({"final_report": "Potential prompt-injection content detected. Provide only incident evidence."},
                Settings.FAST_MODEL_NAME, "needs_human", 0, prompt_version, None, "n/a")

    on_step(StepTrace(step="PromptVersion", what_it_does="Loads prompt template version for this run.",
                      prompt_preview=summarize_text(prompt_template, 180), input_summary=f"mode=g2 version={prompt_version}",
                      output_summary="Prompt template resolved successfully."))

    def _on_step(step: Dict[str, str]):
        on_step(StepTrace(**step))

    executed = run_multiagent_with_trace(prompted_logs, on_step=_on_step)
    stop_reason = str(executed.get("stop_reason", "completed"))
    steps_used = int(executed.get("steps_used", len(executed.get("trace", []))))
    final_text = str(executed["result"].get("final_report", ""))
    evidence_count = count_evidence_markers(final_text + "\n" + str(executed["result"].get("cti_evidence", "")))
    gated_text, gated_stop_reason = apply_action_gating(final_text, high_risk=Settings.is_high_risk_task(clean_logs), evidence_count=evidence_count)
    executed["result"]["final_report"] = gated_text
    if stop_reason != "error" and gated_stop_reason == "needs_human":
        stop_reason = "needs_human"
    policy_ok, policy_status = apply_output_policy_guard(executed["result"]["final_report"])
    if not policy_ok:
        executed["result"]["final_report"] = "Output policy blocked this response due to potentially unsafe content. Please narrow the request to defensive security analysis."
        stop_reason = "needs_human"
    rubric = _evaluate_response_rubric(executed["result"]["final_report"])
    on_step(StepTrace(step="PolicyGuard", what_it_does="Applies output-policy and high-risk action gates.",
                      prompt_preview=f"min_evidence={Settings.MIN_EVIDENCE_FOR_HIGH_RISK}",
                      input_summary=f"evidence_count={evidence_count}",
                      output_reason=f"policy={policy_status}, stop_reason={stop_reason}" if False else None,
                      output_summary=f"policy={policy_status}, stop_reason={stop_reason}"))
    on_step(StepTrace(step="RubricEvaluation", what_it_does="Scores response quality against rubric checks.",
                      prompt_preview="criteria={evidence,severity,actions,clarity}", input_summary=summarize_text(final_text),
                      output_summary=f"score={rubric.get('rubric_score')} label={rubric.get('rubric_label')}"))
    return (executed["result"], Settings.FAST_MODEL_NAME, stop_reason, steps_used, prompt_version, rubric.get("rubric_score"), str(rubric.get("rubric_label", "n/a")))
