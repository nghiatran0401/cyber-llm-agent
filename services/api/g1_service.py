"""G1 single-agent runners for the API service layer."""

from __future__ import annotations

import json
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.agents.g1.agent_with_memory import create_agent_with_memory
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
from .schemas import StepTrace

_AGENT_CACHE: Dict[str, tuple[Any, float]] = {}
_PROMPT_MANAGER = PromptManager()
_EVALUATOR = AgentEvaluator()


def _prune_agent_cache() -> None:
    now = time.time()
    expired = [k for k, (_, created_at) in _AGENT_CACHE.items() if now - created_at > Settings.AGENT_CACHE_TTL_SECONDS]
    for key in expired:
        _AGENT_CACHE.pop(key, None)
    if len(_AGENT_CACHE) > Settings.AGENT_CACHE_MAX_SIZE:
        oldest_key = min(_AGENT_CACHE.items(), key=lambda item: item[1][1])[0]
        _AGENT_CACHE.pop(oldest_key, None)


def _get_or_create_memory_agent(session_id: Optional[str]):
    cache_key = session_id or "__default__"
    _prune_agent_cache()
    if cache_key not in _AGENT_CACHE:
        _AGENT_CACHE[cache_key] = (
            create_agent_with_memory(
                memory_type="buffer",
                max_messages=12,
                max_episodic_items=Settings.MEMORY_MAX_EPISODIC_ITEMS,
                max_semantic_facts=Settings.MEMORY_MAX_SEMANTIC_FACTS,
                recall_top_k=Settings.MEMORY_RECALL_TOP_K,
                session_id=session_id,
                verbose=False,
            ),
            time.time(),
        )
    return _AGENT_CACHE[cache_key][0]


def _resolve_prompt_version(mode: str) -> tuple[str, str]:
    selected = Settings.PROMPT_VERSION_G1 if mode == "g1" else Settings.PROMPT_VERSION_G2
    return selected, _PROMPT_MANAGER.load_prompt(selected)


def _build_prompted_input(prompt_template: str, user_input: str) -> str:
    return f"{prompt_template}\n\nUser input:\n{user_input}\n\nAnalysis:"


def _evaluate_response_rubric(response_text: str) -> Dict[str, Any]:
    if not Settings.ENABLE_RUBRIC_EVAL:
        return {"rubric_score": None, "rubric_label": "disabled", "checks": {}}
    return _EVALUATOR.evaluate_rubric(response_text)


def _run_single_agent_loop(agent: Any, user_input: str) -> tuple[str, str, int]:
    """Execute bounded single-agent loop with deterministic stop reasons."""
    start_time = time.perf_counter()
    response = ""
    steps_used = 0
    stop_reason = "budget_exceeded"

    for step_idx in range(Settings.MAX_AGENT_STEPS):
        if time.perf_counter() - start_time > Settings.MAX_RUNTIME_SECONDS:
            stop_reason = "budget_exceeded"
            break
        steps_used = step_idx + 1
        response = enforce_response_boundaries(agent.run(user_input))
        stop_reason = "completed"
        break

    return response, stop_reason, steps_used


def run_g1_analysis(
    user_input: str,
    session_id: Optional[str] = None,
) -> Tuple[str, List[StepTrace], str, str, int, str, Optional[float], str]:
    """Run G1 analysis and return (response, trace, model, stop_reason, steps, prompt_ver, rubric_score, rubric_label)."""
    clean_input = sanitize_untrusted_text(validate_input(user_input, "input"))
    prompt_version, prompt_template = _resolve_prompt_version("g1")
    prompted_input = _build_prompted_input(prompt_template, clean_input)
    high_risk = Settings.is_high_risk_task(clean_input)
    selected_model = Settings.STRONG_MODEL_NAME if Settings.should_use_strong_model(clean_input) else Settings.FAST_MODEL_NAME
    injection_detected = Settings.ENABLE_PROMPT_INJECTION_GUARD and detect_prompt_injection(clean_input)

    trace: List[StepTrace] = [
        StepTrace(step="InputPreparation", what_it_does="Validates and prepares request for G1 execution.",
                  prompt_preview=summarize_text(prompted_input), input_summary=summarize_text(clean_input),
                  output_summary="Input accepted and formatted."),
        StepTrace(step="RoutingPolicy", what_it_does="Chooses fast or strong model and evidence policy.",
                  prompt_preview=summarize_text(f"high_risk={high_risk} model={selected_model}"),
                  input_summary=f"high_risk={high_risk}", output_summary=f"Selected model: {selected_model}"),
        StepTrace(step="PromptVersion", what_it_does="Loads prompt template version for this run.",
                  prompt_preview=summarize_text(prompt_template, 180), input_summary=f"mode=g1 version={prompt_version}",
                  output_summary="Prompt template resolved successfully."),
        StepTrace(step="SafetyGuard", what_it_does="Detects prompt-injection patterns before execution.",
                  prompt_preview="prompt_injection_guard=enabled", input_summary=summarize_text(clean_input),
                  output_summary=f"injection_detected={injection_detected}"),
    ]

    if injection_detected:
        return (
            "Potential prompt-injection content detected. Please remove control-instruction text and retry with only incident data.",
            trace, selected_model, "needs_human", 0, prompt_version, None, "n/a",
        )

    agent = _get_or_create_memory_agent(session_id)
    response, stop_reason, steps_used = _run_single_agent_loop(agent, prompted_input)
    structured = build_structured_g1_report(response)
    critic_ok, critic_message = critic_validate_structured_output(structured, high_risk=high_risk)
    if not critic_ok:
        response = enforce_response_boundaries(f"{response}\n\nCritic verdict: {critic_message} Please provide more logs, IOC context, or CTI evidence.")
        stop_reason = "needs_human"
    evidence_count = count_evidence_markers(response)
    response, stop_reason = apply_action_gating(response, high_risk=high_risk, evidence_count=evidence_count)
    policy_ok, policy_status = apply_output_policy_guard(response)
    if not policy_ok:
        response = "Output policy blocked this response due to potentially unsafe content. Please narrow the request to defensive security analysis."
        stop_reason = "needs_human"

    trace += [
        StepTrace(step="SingleAgentExecution", what_it_does="Runs a memory-enabled agent with tools.",
                  prompt_preview=summarize_text(prompted_input), input_summary=summarize_text(clean_input),
                  output_summary=summarize_text(response)),
        StepTrace(step="RunControl", what_it_does="Tracks loop stop condition and bounded execution state.",
                  prompt_preview=f"max_steps={Settings.MAX_AGENT_STEPS}", input_summary=f"steps_used={steps_used}",
                  output_summary=f"stop_reason={stop_reason}"),
        StepTrace(step="StructuredOutput", what_it_does="Builds evidence-first structured report from model output.",
                  prompt_preview="schema={severity,findings,recommended_actions,confidence,citations}",
                  input_summary=summarize_text(response), output_summary=summarize_text(json.dumps(structured, ensure_ascii=True))),
        StepTrace(step="CriticReview", what_it_does="Validates structured output quality and evidence requirements.",
                  prompt_preview=f"high_risk={high_risk}", input_summary=summarize_text(json.dumps(structured, ensure_ascii=True)),
                  output_summary=f"pass={critic_ok}; reason={critic_message}"),
        StepTrace(step="PolicyGuard", what_it_does="Applies output-policy and high-risk action gates.",
                  prompt_preview=f"min_evidence={Settings.MIN_EVIDENCE_FOR_HIGH_RISK}",
                  input_summary=f"high_risk={high_risk}, evidence_count={evidence_count}",
                  output_summary=f"policy={policy_status}, stop_reason={stop_reason}"),
    ]
    rubric = _evaluate_response_rubric(response)
    trace.append(StepTrace(step="RubricEvaluation", what_it_does="Scores response quality against rubric checks.",
                           prompt_preview="criteria={evidence,severity,actions,clarity}", input_summary=summarize_text(response),
                           output_summary=f"score={rubric.get('rubric_score')} label={rubric.get('rubric_label')}"))
    return (response, trace, selected_model, stop_reason, steps_used, prompt_version, rubric.get("rubric_score"), str(rubric.get("rubric_label", "n/a")))


def run_g1_analysis_with_progress(
    user_input: str,
    on_step: Callable[[StepTrace], None],
    session_id: Optional[str] = None,
) -> Tuple[str, str, str, int, str, Optional[float], str]:
    """Run G1 analysis, emitting each step immediately via on_step callback."""
    clean_input = sanitize_untrusted_text(validate_input(user_input, "input"))
    prompt_version, prompt_template = _resolve_prompt_version("g1")
    prompted_input = _build_prompted_input(prompt_template, clean_input)
    high_risk = Settings.is_high_risk_task(clean_input)
    selected_model = Settings.STRONG_MODEL_NAME if Settings.should_use_strong_model(clean_input) else Settings.FAST_MODEL_NAME
    injection_detected = Settings.ENABLE_PROMPT_INJECTION_GUARD and detect_prompt_injection(clean_input)

    on_step(StepTrace(step="InputPreparation", what_it_does="Validates and prepares request for G1 execution.",
                      prompt_preview=summarize_text(prompted_input), input_summary=summarize_text(clean_input),
                      output_summary="Input accepted and formatted."))
    on_step(StepTrace(step="RoutingPolicy", what_it_does="Chooses fast or strong model.",
                      prompt_preview=summarize_text(f"high_risk={high_risk} model={selected_model}"),
                      input_summary=f"high_risk={high_risk}", output_summary=f"Selected model: {selected_model}"))
    on_step(StepTrace(step="PromptVersion", what_it_does="Loads prompt template version for this run.",
                      prompt_preview=summarize_text(prompt_template, 180), input_summary=f"mode=g1 version={prompt_version}",
                      output_summary="Prompt template resolved successfully."))
    on_step(StepTrace(step="SafetyGuard", what_it_does="Detects prompt-injection patterns before execution.",
                      prompt_preview="prompt_injection_guard=enabled", input_summary=summarize_text(clean_input),
                      output_summary=f"injection_detected={injection_detected}"))

    if injection_detected:
        return ("Potential prompt-injection content detected. Please remove control-instruction text and retry.",
                selected_model, "needs_human", 0, prompt_version, None, "n/a")

    agent = _get_or_create_memory_agent(session_id)
    response, stop_reason, steps_used = _run_single_agent_loop(agent, prompted_input)
    structured = build_structured_g1_report(response)
    critic_ok, critic_message = critic_validate_structured_output(structured, high_risk=high_risk)
    if not critic_ok:
        response = enforce_response_boundaries(f"{response}\n\nCritic verdict: {critic_message} Please provide more logs, IOC context, or CTI evidence.")
        stop_reason = "needs_human"
    evidence_count = count_evidence_markers(response)
    response, stop_reason = apply_action_gating(response, high_risk=high_risk, evidence_count=evidence_count)
    policy_ok, policy_status = apply_output_policy_guard(response)
    if not policy_ok:
        response = "Output policy blocked this response due to potentially unsafe content. Please narrow the request to defensive security analysis."
        stop_reason = "needs_human"

    on_step(StepTrace(step="SingleAgentExecution", what_it_does="Runs a memory-enabled agent with tools.",
                      prompt_preview=summarize_text(prompted_input), input_summary=summarize_text(clean_input),
                      output_summary=summarize_text(response)))
    on_step(StepTrace(step="RunControl", what_it_does="Tracks loop stop condition.",
                      prompt_preview=f"max_steps={Settings.MAX_AGENT_STEPS}", input_summary=f"steps_used={steps_used}",
                      output_summary=f"stop_reason={stop_reason}"))
    on_step(StepTrace(step="PolicyGuard", what_it_does="Applies output-policy and high-risk action gates.",
                      prompt_preview=f"min_evidence={Settings.MIN_EVIDENCE_FOR_HIGH_RISK}",
                      input_summary=f"high_risk={high_risk}, evidence_count={evidence_count}",
                      output_summary=f"policy={policy_status}, stop_reason={stop_reason}"))
    rubric = _evaluate_response_rubric(response)
    on_step(StepTrace(step="RubricEvaluation", what_it_does="Scores response quality against rubric checks.",
                      prompt_preview="criteria={evidence,severity,actions,clarity}", input_summary=summarize_text(response),
                      output_summary=f"score={rubric.get('rubric_score')} label={rubric.get('rubric_label')}"))
    return (response, selected_model, stop_reason, steps_used, prompt_version, rubric.get("rubric_score"), str(rubric.get("rubric_label", "n/a")))


def run_chat(user_input: str, mode: str = "g1", session_id: Optional[str] = None):
    """Run chat in the requested mode (g1 or g2) with shape-aligned output."""
    from .g2_service import run_g2_analysis

    clean_input = validate_input(user_input, "input")
    if mode == "g2":
        result, trace, model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label = run_g2_analysis(clean_input)
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
        result, model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label = run_g2_analysis_with_progress(clean_input, on_step=on_step)
        return (str(result.get("final_report", "")), model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label)
    return run_g1_analysis_with_progress(clean_input, on_step=on_step, session_id=session_id)
