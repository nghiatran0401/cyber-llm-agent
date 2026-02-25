"""Application service layer for API endpoints."""

from __future__ import annotations

import json
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.agents.g1.agent_with_memory import create_agent_with_memory
from src.agents.g2.multiagent_system import run_multiagent_with_trace
from src.config.settings import Settings
from src.sandbox.owasp_sandbox import append_event_to_live_log, event_to_analysis_text, generate_event, list_scenarios
from src.utils.evaluator import AgentEvaluator
from src.utils.prompt_manager import PromptManager
from src.utils.prompt_templates import render_prompt_template

from .schemas import StepTrace

MAX_INPUT_CHARS = 50_000
MAX_EVENT_TEXT_CHARS = 10_000
MAX_EVENT_KEYS = 32
_AGENT_CACHE: Dict[str, tuple[Any, float]] = {}
_SEVERITY_ORDER = ("critical", "high", "medium", "low")
_PROMPT_INJECTION_MARKERS = (
    "ignore previous instructions",
    "ignore all prior",
    "system prompt",
    "developer message",
    "reveal hidden instructions",
    "bypass policy",
    "disable guardrails",
)
_OUTPUT_POLICY_DENYLIST = (
    "BEGIN PRIVATE KEY",
    "OPENAI_API_KEY=",
    "authorization: bearer ",
    "how to weaponize",
    "drop table users",
)
_PROMPT_MANAGER = PromptManager()
_EVALUATOR = AgentEvaluator()


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


def _sanitize_untrusted_text(text: str) -> str:
    # Strip non-printable control chars and keep deterministic whitespace.
    sanitized = "".join(ch for ch in str(text or "") if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    return sanitized.replace("\x00", "").strip()


def _detect_prompt_injection(text: str) -> bool:
    content = (text or "").lower()
    return any(marker in content for marker in _PROMPT_INJECTION_MARKERS)


def _count_evidence_markers(text: str) -> int:
    content = (text or "").lower()
    markers = (
        content.count("source:"),
        content.count("#chunk-"),
        content.count("citation"),
        content.count("cti"),
    )
    return sum(markers)


def _apply_output_policy_guard(text: str) -> tuple[bool, str]:
    if not Settings.ENABLE_OUTPUT_POLICY_GUARD:
        return True, "disabled"
    content = text or ""
    for blocked in _OUTPUT_POLICY_DENYLIST:
        if blocked.lower() in content.lower():
            return False, f"blocked_content:{blocked}"
    return True, "pass"


def _apply_action_gating(
    response: str,
    *,
    high_risk: bool,
    evidence_count: int,
) -> tuple[str, str]:
    if not high_risk:
        return response, "completed"

    if evidence_count < Settings.MIN_EVIDENCE_FOR_HIGH_RISK:
        gated = (
            f"{response}\n\nSafety gate: high-risk recommendation lacks required evidence "
            f"(minimum={Settings.MIN_EVIDENCE_FOR_HIGH_RISK}, observed={evidence_count})."
        )
        return _enforce_response_boundaries(gated), "needs_human"

    if Settings.REQUIRE_HUMAN_APPROVAL_HIGH_RISK:
        gated = (
            f"{response}\n\nSafety gate: high-risk actions require explicit human approval before execution."
        )
        return _enforce_response_boundaries(gated), "needs_human"

    return response, "completed"


def _extract_bullets(section_name: str, text: str) -> List[str]:
    pattern = re.compile(rf"{re.escape(section_name)}\s*:?\s*(.*?)(?:\n\s*\n|$)", re.IGNORECASE | re.DOTALL)
    match = pattern.search(text or "")
    if not match:
        return []
    block = match.group(1)
    bullets = []
    for line in block.splitlines():
        stripped = line.strip()
        if stripped.startswith(("- ", "* ")):
            bullets.append(stripped[2:].strip())
    return [bullet for bullet in bullets if bullet]


def _infer_severity(response_text: str) -> str:
    lower = (response_text or "").lower()
    for severity in _SEVERITY_ORDER:
        if severity in lower:
            return severity
    return "unknown"


def _extract_citations(response_text: str) -> List[str]:
    citations: List[str] = []
    for raw_line in (response_text or "").splitlines():
        line = raw_line.strip()
        if line.lower().startswith("source:"):
            citations.append(line)
        elif "#chunk-" in line:
            citations.append(line.lstrip("- ").strip())
    deduped: List[str] = []
    for citation in citations:
        if citation not in deduped:
            deduped.append(citation)
    return deduped


def _build_structured_g1_report(response_text: str) -> Dict[str, Any]:
    findings = _extract_bullets("findings", response_text)
    actions = _extract_bullets("recommended actions", response_text) or _extract_bullets(
        "recommended action", response_text
    )
    if not findings:
        findings = [_summarize_text(response_text, 320)]
    confidence = "low"
    lower = (response_text or "").lower()
    if "confidence: high" in lower:
        confidence = "high"
    elif "confidence: medium" in lower:
        confidence = "medium"
    return {
        "severity": _infer_severity(response_text),
        "findings": findings,
        "recommended_actions": actions,
        "confidence": confidence,
        "citations": _extract_citations(response_text),
    }


def _critic_validate_structured_output(structured: Dict[str, Any], high_risk: bool) -> tuple[bool, str]:
    findings = structured.get("findings") or []
    actions = structured.get("recommended_actions") or []
    citations = structured.get("citations") or []
    if not findings:
        return False, "Missing findings in structured output."
    if high_risk and not actions:
        return False, "High-risk response missing recommended actions."
    if high_risk and not citations:
        return False, "High-risk response missing evidence citations."
    return True, "Structured output passed critic checks."


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
        # Single-step deterministic execution; policy gates can still override stop_reason later.
        stop_reason = "completed"
        break

    return response, stop_reason, steps_used


def _resolve_prompt_version(mode: str) -> tuple[str, str]:
    selected = Settings.PROMPT_VERSION_G1 if mode == "g1" else Settings.PROMPT_VERSION_G2
    return selected, _PROMPT_MANAGER.load_prompt(selected)


def _build_prompted_input(prompt_template: str, user_input: str) -> str:
    return f"{prompt_template}\n\nUser input:\n{user_input}\n\nAnalysis:"


def _evaluate_response_rubric(response_text: str) -> Dict[str, Any]:
    if not Settings.ENABLE_RUBRIC_EVAL:
        return {"rubric_score": None, "rubric_label": "disabled", "checks": {}}
    return _EVALUATOR.evaluate_rubric(response_text)


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
            max_episodic_items=Settings.MEMORY_MAX_EPISODIC_ITEMS,
            max_semantic_facts=Settings.MEMORY_MAX_SEMANTIC_FACTS,
            recall_top_k=Settings.MEMORY_RECALL_TOP_K,
            session_id=session_id,
            verbose=False,
            ),
            time.time(),
        )
    return _AGENT_CACHE[cache_key][0]


def run_g1_analysis(
    user_input: str,
    session_id: Optional[str] = None,
) -> Tuple[str, List[StepTrace], str, str, int, str, Optional[float], str]:
    """Run G1 analysis and return response text, trace, model, stop reason, and steps."""
    clean_input = _sanitize_untrusted_text(_validate_input(user_input, "input"))
    prompt_version, prompt_template = _resolve_prompt_version("g1")
    prompted_input = _build_prompted_input(prompt_template, clean_input)
    strong = Settings.should_use_strong_model(clean_input)
    high_risk = Settings.is_high_risk_task(clean_input)
    selected_model = Settings.STRONG_MODEL_NAME if strong else Settings.FAST_MODEL_NAME
    injection_detected = Settings.ENABLE_PROMPT_INJECTION_GUARD and _detect_prompt_injection(clean_input)

    trace: List[StepTrace] = [
        StepTrace(
            step="InputPreparation",
            what_it_does="Validates and prepares request for G1 execution.",
            prompt_preview=_summarize_text(prompted_input),
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
    trace.append(
        StepTrace(
            step="PromptVersion",
            what_it_does="Loads prompt template version for this run.",
            prompt_preview=_summarize_text(prompt_template, 180),
            input_summary=f"mode=g1 version={prompt_version}",
            output_summary="Prompt template resolved successfully.",
        )
    )
    trace.append(
        StepTrace(
            step="SafetyGuard",
            what_it_does="Detects prompt-injection patterns before execution.",
            prompt_preview="prompt_injection_guard=enabled",
            input_summary=_summarize_text(clean_input),
            output_summary=f"injection_detected={injection_detected}",
        )
    )
    if injection_detected:
        blocked = (
            "Potential prompt-injection content detected. "
            "Please remove control-instruction text and retry with only incident data."
        )
        return (
            blocked,
            trace,
            selected_model,
            "needs_human",
            0,
            prompt_version,
            None,
            "n/a",
        )

    agent = _get_or_create_memory_agent(session_id)
    response, stop_reason, steps_used = _run_single_agent_loop(agent, prompted_input)
    structured = _build_structured_g1_report(response)
    critic_ok, critic_message = _critic_validate_structured_output(structured, high_risk=high_risk)
    if not critic_ok:
        response = _enforce_response_boundaries(
            f"{response}\n\nCritic verdict: {critic_message} Please provide more logs, IOC context, or CTI evidence."
        )
        stop_reason = "needs_human"
    evidence_count = _count_evidence_markers(response)
    response, stop_reason = _apply_action_gating(
        response,
        high_risk=high_risk,
        evidence_count=evidence_count,
    )
    policy_ok, policy_status = _apply_output_policy_guard(response)
    if not policy_ok:
        response = (
            "Output policy blocked this response due to potentially unsafe content. "
            "Please narrow the request to defensive security analysis."
        )
        stop_reason = "needs_human"
    trace.append(
        StepTrace(
            step="SingleAgentExecution",
            what_it_does="Runs a memory-enabled agent with tools.",
            prompt_preview=_summarize_text(prompted_input),
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
    trace.append(
        StepTrace(
            step="StructuredOutput",
            what_it_does="Builds evidence-first structured report from model output.",
            prompt_preview="schema={severity, findings, recommended_actions, confidence, citations}",
            input_summary=_summarize_text(response),
            output_summary=_summarize_text(json.dumps(structured, ensure_ascii=True)),
        )
    )
    trace.append(
        StepTrace(
            step="CriticReview",
            what_it_does="Validates structured output quality and evidence requirements.",
            prompt_preview=f"high_risk={high_risk}",
            input_summary=_summarize_text(json.dumps(structured, ensure_ascii=True)),
            output_summary=f"pass={critic_ok}; reason={critic_message}",
        )
    )
    trace.append(
        StepTrace(
            step="PolicyGuard",
            what_it_does="Applies output-policy and high-risk action gates.",
            prompt_preview=(
                f"min_evidence={Settings.MIN_EVIDENCE_FOR_HIGH_RISK}, "
                f"human_approval={Settings.REQUIRE_HUMAN_APPROVAL_HIGH_RISK}"
            ),
            input_summary=f"high_risk={high_risk}, evidence_count={evidence_count}",
            output_summary=f"policy={policy_status}, stop_reason={stop_reason}",
        )
    )
    rubric = _evaluate_response_rubric(response)
    trace.append(
        StepTrace(
            step="RubricEvaluation",
            what_it_does="Scores response quality against rubric checks.",
            prompt_preview="criteria={evidence,severity,actions,clarity}",
            input_summary=_summarize_text(response),
            output_summary=f"score={rubric.get('rubric_score')} label={rubric.get('rubric_label')}",
        )
    )
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


def run_g1_analysis_with_progress(
    user_input: str,
    on_step: Callable[[StepTrace], None],
    session_id: Optional[str] = None,
) -> Tuple[str, str, str, int, str, Optional[float], str]:
    """Run G1 with progressive step callbacks."""
    clean_input = _sanitize_untrusted_text(_validate_input(user_input, "input"))
    prompt_version, prompt_template = _resolve_prompt_version("g1")
    prompted_input = _build_prompted_input(prompt_template, clean_input)
    strong = Settings.should_use_strong_model(clean_input)
    high_risk = Settings.is_high_risk_task(clean_input)
    selected_model = Settings.STRONG_MODEL_NAME if strong else Settings.FAST_MODEL_NAME
    injection_detected = Settings.ENABLE_PROMPT_INJECTION_GUARD and _detect_prompt_injection(clean_input)

    step1 = StepTrace(
        step="InputPreparation",
        what_it_does="Validates and prepares request for G1 execution.",
        prompt_preview=_summarize_text(prompted_input),
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
    on_step(
        StepTrace(
            step="PromptVersion",
            what_it_does="Loads prompt template version for this run.",
            prompt_preview=_summarize_text(prompt_template, 180),
            input_summary=f"mode=g1 version={prompt_version}",
            output_summary="Prompt template resolved successfully.",
        )
    )
    on_step(
        StepTrace(
            step="SafetyGuard",
            what_it_does="Detects prompt-injection patterns before execution.",
            prompt_preview="prompt_injection_guard=enabled",
            input_summary=_summarize_text(clean_input),
            output_summary=f"injection_detected={injection_detected}",
        )
    )
    if injection_detected:
        return (
            "Potential prompt-injection content detected. Please remove control-instruction text and retry.",
            selected_model,
            "needs_human",
            0,
            prompt_version,
            None,
            "n/a",
        )

    agent = _get_or_create_memory_agent(session_id)
    response, stop_reason, steps_used = _run_single_agent_loop(agent, prompted_input)
    structured = _build_structured_g1_report(response)
    critic_ok, critic_message = _critic_validate_structured_output(structured, high_risk=high_risk)
    if not critic_ok:
        response = _enforce_response_boundaries(
            f"{response}\n\nCritic verdict: {critic_message} Please provide more logs, IOC context, or CTI evidence."
        )
        stop_reason = "needs_human"
    evidence_count = _count_evidence_markers(response)
    response, stop_reason = _apply_action_gating(
        response,
        high_risk=high_risk,
        evidence_count=evidence_count,
    )
    policy_ok, policy_status = _apply_output_policy_guard(response)
    if not policy_ok:
        response = (
            "Output policy blocked this response due to potentially unsafe content. "
            "Please narrow the request to defensive security analysis."
        )
        stop_reason = "needs_human"
    step3 = StepTrace(
        step="SingleAgentExecution",
        what_it_does="Runs a memory-enabled agent with tools.",
        prompt_preview=_summarize_text(prompted_input),
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
    on_step(
        StepTrace(
            step="StructuredOutput",
            what_it_does="Builds evidence-first structured report from model output.",
            prompt_preview="schema={severity, findings, recommended_actions, confidence, citations}",
            input_summary=_summarize_text(response),
            output_summary=_summarize_text(json.dumps(structured, ensure_ascii=True)),
        )
    )
    on_step(
        StepTrace(
            step="CriticReview",
            what_it_does="Validates structured output quality and evidence requirements.",
            prompt_preview=f"high_risk={high_risk}",
            input_summary=_summarize_text(json.dumps(structured, ensure_ascii=True)),
            output_summary=f"pass={critic_ok}; reason={critic_message}",
        )
    )
    on_step(
        StepTrace(
            step="PolicyGuard",
            what_it_does="Applies output-policy and high-risk action gates.",
            prompt_preview=(
                f"min_evidence={Settings.MIN_EVIDENCE_FOR_HIGH_RISK}, "
                f"human_approval={Settings.REQUIRE_HUMAN_APPROVAL_HIGH_RISK}"
            ),
            input_summary=f"high_risk={high_risk}, evidence_count={evidence_count}",
            output_summary=f"policy={policy_status}, stop_reason={stop_reason}",
        )
    )
    rubric = _evaluate_response_rubric(response)
    on_step(
        StepTrace(
            step="RubricEvaluation",
            what_it_does="Scores response quality against rubric checks.",
            prompt_preview="criteria={evidence,severity,actions,clarity}",
            input_summary=_summarize_text(response),
            output_summary=f"score={rubric.get('rubric_score')} label={rubric.get('rubric_label')}",
        )
    )
    return (
        response,
        selected_model,
        stop_reason,
        steps_used,
        prompt_version,
        rubric.get("rubric_score"),
        str(rubric.get("rubric_label", "n/a")),
    )


def run_g2_analysis(
    log_input: str,
) -> Tuple[Dict[str, Any], List[StepTrace], str, str, int, str, Optional[float], str]:
    """Run G2 workflow and return result, trace, model, stop reason, and steps."""
    clean_logs = _sanitize_untrusted_text(_validate_input(log_input, "input"))
    prompt_version, prompt_template = _resolve_prompt_version("g2")
    prompted_logs = _build_prompted_input(prompt_template, clean_logs)
    injection_detected = Settings.ENABLE_PROMPT_INJECTION_GUARD and _detect_prompt_injection(clean_logs)
    if injection_detected:
        trace = [
            StepTrace(
                step="SafetyGuard",
                what_it_does="Detects prompt-injection patterns before execution.",
                prompt_preview="prompt_injection_guard=enabled",
                input_summary=_summarize_text(clean_logs),
                output_summary="injection_detected=True",
            )
        ]
        return (
            {"final_report": "Potential prompt-injection content detected. Provide only incident evidence."},
            trace,
            Settings.FAST_MODEL_NAME,
            "needs_human",
            0,
            prompt_version,
            None,
            "n/a",
        )
    executed = run_multiagent_with_trace(prompted_logs)
    result = executed["result"]
    trace = [StepTrace(**step) for step in executed["trace"]]
    trace.insert(
        0,
        StepTrace(
            step="PromptVersion",
            what_it_does="Loads prompt template version for this run.",
            prompt_preview=_summarize_text(prompt_template, 180),
            input_summary=f"mode=g2 version={prompt_version}",
            output_summary="Prompt template resolved successfully.",
        ),
    )
    stop_reason = str(executed.get("stop_reason", "completed"))
    steps_used = int(executed.get("steps_used", len(trace)))
    final_text = str(result.get("final_report", ""))
    evidence_count = _count_evidence_markers(final_text + "\n" + str(result.get("cti_evidence", "")))
    gated_text, gated_stop_reason = _apply_action_gating(
        final_text,
        high_risk=Settings.is_high_risk_task(clean_logs),
        evidence_count=evidence_count,
    )
    result["final_report"] = gated_text
    stop_reason = "needs_human" if stop_reason != "error" and gated_stop_reason == "needs_human" else stop_reason
    policy_ok, policy_status = _apply_output_policy_guard(result["final_report"])
    if not policy_ok:
        result["final_report"] = (
            "Output policy blocked this response due to potentially unsafe content. "
            "Please narrow the request to defensive security analysis."
        )
        stop_reason = "needs_human"
    rubric = _evaluate_response_rubric(result["final_report"])
    trace.append(
        StepTrace(
            step="PolicyGuard",
            what_it_does="Applies output-policy and high-risk action gates.",
            prompt_preview=(
                f"min_evidence={Settings.MIN_EVIDENCE_FOR_HIGH_RISK}, "
                f"human_approval={Settings.REQUIRE_HUMAN_APPROVAL_HIGH_RISK}"
            ),
            input_summary=f"evidence_count={evidence_count}",
            output_summary=f"policy={policy_status}, stop_reason={stop_reason}",
        )
    )
    trace.append(
        StepTrace(
            step="RubricEvaluation",
            what_it_does="Scores response quality against rubric checks.",
            prompt_preview="criteria={evidence,severity,actions,clarity}",
            input_summary=_summarize_text(final_text),
            output_summary=f"score={rubric.get('rubric_score')} label={rubric.get('rubric_label')}",
        )
    )
    return (
        result,
        trace,
        Settings.FAST_MODEL_NAME,
        stop_reason,
        steps_used,
        prompt_version,
        rubric.get("rubric_score"),
        str(rubric.get("rubric_label", "n/a")),
    )


def run_g2_analysis_with_progress(
    log_input: str,
    on_step: Callable[[StepTrace], None],
) -> Tuple[Dict[str, Any], str, str, int, str, Optional[float], str]:
    """Run G2 and emit each step as soon as it completes."""
    clean_logs = _sanitize_untrusted_text(_validate_input(log_input, "input"))
    prompt_version, prompt_template = _resolve_prompt_version("g2")
    prompted_logs = _build_prompted_input(prompt_template, clean_logs)
    injection_detected = Settings.ENABLE_PROMPT_INJECTION_GUARD and _detect_prompt_injection(clean_logs)
    if injection_detected:
        on_step(
            StepTrace(
                step="SafetyGuard",
                what_it_does="Detects prompt-injection patterns before execution.",
                prompt_preview="prompt_injection_guard=enabled",
                input_summary=_summarize_text(clean_logs),
                output_summary="injection_detected=True",
            )
        )
        return (
            {"final_report": "Potential prompt-injection content detected. Provide only incident evidence."},
            Settings.FAST_MODEL_NAME,
            "needs_human",
            0,
            prompt_version,
            None,
            "n/a",
        )
    on_step(
        StepTrace(
            step="PromptVersion",
            what_it_does="Loads prompt template version for this run.",
            prompt_preview=_summarize_text(prompt_template, 180),
            input_summary=f"mode=g2 version={prompt_version}",
            output_summary="Prompt template resolved successfully.",
        )
    )

    def _on_step(step: Dict[str, str]):
        on_step(StepTrace(**step))

    executed = run_multiagent_with_trace(prompted_logs, on_step=_on_step)
    stop_reason = str(executed.get("stop_reason", "completed"))
    steps_used = int(executed.get("steps_used", len(executed.get("trace", []))))
    final_text = str(executed["result"].get("final_report", ""))
    evidence_count = _count_evidence_markers(
        final_text + "\n" + str(executed["result"].get("cti_evidence", ""))
    )
    gated_text, gated_stop_reason = _apply_action_gating(
        final_text,
        high_risk=Settings.is_high_risk_task(clean_logs),
        evidence_count=evidence_count,
    )
    executed["result"]["final_report"] = gated_text
    stop_reason = "needs_human" if stop_reason != "error" and gated_stop_reason == "needs_human" else stop_reason
    policy_ok, policy_status = _apply_output_policy_guard(executed["result"]["final_report"])
    if not policy_ok:
        executed["result"]["final_report"] = (
            "Output policy blocked this response due to potentially unsafe content. "
            "Please narrow the request to defensive security analysis."
        )
        stop_reason = "needs_human"
    on_step(
        StepTrace(
            step="PolicyGuard",
            what_it_does="Applies output-policy and high-risk action gates.",
            prompt_preview=(
                f"min_evidence={Settings.MIN_EVIDENCE_FOR_HIGH_RISK}, "
                f"human_approval={Settings.REQUIRE_HUMAN_APPROVAL_HIGH_RISK}"
            ),
            input_summary=f"evidence_count={evidence_count}",
            output_summary=f"policy={policy_status}, stop_reason={stop_reason}",
        )
    )
    rubric = _evaluate_response_rubric(executed["result"]["final_report"])
    on_step(
        StepTrace(
            step="RubricEvaluation",
            what_it_does="Scores response quality against rubric checks.",
            prompt_preview="criteria={evidence,severity,actions,clarity}",
            input_summary=_summarize_text(final_text),
            output_summary=f"score={rubric.get('rubric_score')} label={rubric.get('rubric_label')}",
        )
    )
    return (
        executed["result"],
        Settings.FAST_MODEL_NAME,
        stop_reason,
        steps_used,
        prompt_version,
        rubric.get("rubric_score"),
        str(rubric.get("rubric_label", "n/a")),
    )


def run_chat(user_input: str, mode: str = "g1", session_id: Optional[str] = None):
    """Run chat in requested mode with shape-aligned output."""
    clean_input = _validate_input(user_input, "input")
    if mode == "g2":
        result, trace, model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label = run_g2_analysis(
            clean_input
        )
        return (
            result.get("final_report", ""),
            trace,
            model,
            stop_reason,
            steps_used,
            prompt_version,
            rubric_score,
            rubric_label,
        )
    response, trace, model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label = run_g1_analysis(
        clean_input,
        session_id=session_id,
    )
    return response, trace, model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label


def run_workspace_with_progress(
    *,
    task: str,
    mode: str,
    user_input: str,
    on_step: Callable[[StepTrace], None],
    session_id: Optional[str] = None,
) -> Tuple[str, str, str, int, str, Optional[float], str]:
    """Run workspace request and emit progress steps for UI streaming."""
    clean_input = _validate_input(user_input, "input")
    normalized_task = (task or "chat").lower()
    normalized_mode = (mode or "g1").lower()

    if normalized_mode == "g2":
        result, model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label = (
            run_g2_analysis_with_progress(clean_input, on_step=on_step)
        )
        return (
            str(result.get("final_report", "")),
            model,
            stop_reason,
            steps_used,
            prompt_version,
            rubric_score,
            rubric_label,
        )

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
    prompt = render_prompt_template(
        "service/sandbox_analysis.txt",
        event_text=event_text,
    )
    return run_g1_analysis(prompt, session_id=session_id)


def get_sandbox_scenarios() -> List[str]:
    """Return supported sandbox scenario keys."""
    return list_scenarios()


def now_ms() -> float:
    return time.perf_counter() * 1000
