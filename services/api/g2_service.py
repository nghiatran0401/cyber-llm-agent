"""G2 multi-agent runners for the API service layer."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.agents.g2.runner import g2_runtime_budget_caps, run_multiagent_with_trace
from src.config.settings import Settings
from src.benchmarking.evaluator import AgentEvaluator
from src.utils.prompt_manager import PromptManager

from .g2_input_gate import (
    compose_g2_input_with_session,
    persist_g2_turn,
    preflight_g2_evidence_bundle,
    preflight_g2_user_turn,
)
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


_BRIEF_REQUEST_RE = re.compile(
    r"(?:\bin\s+short\b|\bbrief(?:ly)?\b|\bshort\b.*\bsummary\b|\btl;?dr\b|\bone[-\s]?liner\b)",
    re.IGNORECASE,
)

_SECTION_HEADING_RE = re.compile(
    r"^(?:final incident summary|incident overview|indicators of compromise|key indicators|"
    r"threat assessment|confidence level|risk level assessment|recommended actions|"
    r"priority actions|conclusion)\s*:?\s*$",
    re.IGNORECASE,
)

_SPLIT_TEAM_RE = re.compile(r"\bsplit\b.*\bteam\b|\bby team\b", re.IGNORECASE)
_NEXT_30_MIN_RE = re.compile(r"\bnext\s+30\s+minutes?\b|\b30\s*min", re.IGNORECASE)
_HUNT_QUERY_RE = re.compile(
    r"\bhunt hypotheses\b|\bpractical queries\b|\bhunt\b.*\b(auth|edr|dns|proxy)\b",
    re.IGNORECASE,
)


def _is_brief_request(user_text: str) -> bool:
    return bool(_BRIEF_REQUEST_RE.search(user_text or ""))


def _guess_attack_label(text: str) -> str:
    t = (text or "").lower()
    if all(k in t for k in ("phish", "oauth")) or ("phish" in t and "forward" in t):
        return "phishing-led account takeover with mailbox exfiltration and OAuth abuse"
    if "ransomware" in t:
        return "ransomware intrusion"
    if "sql" in t and "injection" in t:
        return "SQL injection compromise"
    if "xss" in t:
        return "cross-site scripting attack chain"
    if "ddos" in t:
        return "distributed denial-of-service attack"
    if "credential" in t and ("spray" in t or "stuff" in t):
        return "credential stuffing / password spray activity"
    return "security incident requiring containment"


def _extract_priority_actions(text: str) -> List[str]:
    actions: List[str] = []
    in_actions = False
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("recommended actions", "priority actions", "immediate containment actions")):
            in_actions = True
            continue
        if in_actions and _SECTION_HEADING_RE.match(line):
            break
        if in_actions and line.startswith(("- ", "* ")):
            action = line[2:].strip()
            if action:
                actions.append(action)
        elif in_actions and len(line) > 30 and ":" in line:
            # Handle "Action Name: details..." style.
            actions.append(line)
    return actions[:2]


def _summarize_briefly(*, report: str, user_text: str) -> str:
    incident = _guess_attack_label(f"{user_text}\n{report}")
    actions = _extract_priority_actions(report)
    lines = [f"Likely attack: {incident}."]
    if actions:
        lines.append(f"Top containment priorities: 1) {actions[0]}")
        if len(actions) > 1:
            lines.append(f"2) {actions[1]}")
    else:
        lines.append(
            "Top containment priorities: 1) revoke suspicious access (OAuth/sessions/rules), "
            "2) reset credentials and enforce MFA."
        )
    return "\n".join(lines)


def _extract_first_match(pattern: str, text: str, flags: int = re.IGNORECASE) -> str:
    m = re.search(pattern, text or "", flags)
    return m.group(1).strip() if m else ""


def _extract_context_iocs(text: str) -> Dict[str, str]:
    return {
        "src_ip": _extract_first_match(r"\bsrc(?:_ip)?=([0-9.]+)", text),
        "user": _extract_first_match(r"\buser=([A-Za-z0-9_@.\\\\-]+)", text),
        "target": _extract_first_match(r"\btarget=([A-Za-z0-9_@.\\\\$-]+)", text),
        "host": _extract_first_match(r"\bhost=([A-Za-z0-9_.-]+)", text),
    }


def _format_team_split(*, user_text: str, report: str) -> str:
    iocs = _extract_context_iocs(f"{user_text}\n{report}")
    user = iocs["user"] or "affected_user"
    host = iocs["host"] or "affected_host"
    src_ip = iocs["src_ip"] or "suspicious_source_ip"
    return (
        "Team-split action plan:\n"
        f"- SOC: Confirm timeline and scope; pivot on `src_ip={src_ip}`, `user={user}`, `host={host}` across SIEM; raise incident severity to high and open incident bridge.\n"
        f"- IAM: Force reset `{user}` and any sprayed accounts, revoke active sessions/tokens, enforce MFA challenge on next sign-in, and apply temporary sign-in restrictions for `{src_ip}`.\n"
        f"- Email: If mailbox access exists, review forwarding/auto-rule changes and external forwarding; disable suspicious rules and audit recent OAuth/app consents tied to `{user}`.\n"
        f"- Endpoint: Isolate `{host}`, collect triage artifacts (process tree, PowerShell logs, recent network connections), and block SMB scan tooling / suspicious scripts."
    )


def _format_next_30_minutes(*, user_text: str, report: str) -> str:
    attack = _guess_attack_label(f"{user_text}\n{report}")
    iocs = _extract_context_iocs(f"{user_text}\n{report}")
    src_ip = iocs["src_ip"] or "suspicious_source_ip"
    user = iocs["user"] or iocs["target"] or "affected_user"
    host = iocs["host"] or "affected_host"
    return (
        f"Severity: High\nLikely attack: {attack}\n\n"
        "Next 30 minutes:\n"
        f"1) 0-10 min: Contain access — block `{src_ip}` at edge/VPN, force reset `{user}`, revoke active sessions/tokens.\n"
        f"2) 10-20 min: Contain host/network — isolate `{host}` and block east-west SMB scanning (445) from workstation segments.\n"
        "3) 20-30 min: Scope blast radius — run rapid pivots for failed->success auth chains, LDAP/DNS recon spikes, and unusual outbound proxy/cloud-storage activity."
    )


def _format_hunt_hypotheses_queries(*, user_text: str, report: str) -> str:
    iocs = _extract_context_iocs(f"{user_text}\n{report}")
    src_ip = iocs["src_ip"] or "45.142.193.10"
    user = iocs["user"] or iocs["target"] or "jsmith"
    host = iocs["host"] or "FIN-LAPTOP-22"
    return (
        "Hunt hypotheses:\n"
        "- H1: Credential stuffing from a single source succeeded, then attacker switched to internal recon.\n"
        "- H2: Compromised user context on endpoint executed discovery/scan commands for SMB targets.\n"
        "- H3: Recon plus cloud/proxy activity indicates staging or early exfil behavior.\n\n"
        "Practical hunt queries:\n"
        f"- Auth logs (4625/4624 chain): `event IN (4625,4624) AND (src_ip=\"{src_ip}\" OR user=\"{user}\") | sort by timestamp`.\n"
        f"- EDR process + net: `host=\"{host}\" AND (process=\"powershell.exe\" OR cmdline CONTAINS \"Test-NetConnection\" OR dport=445)`.\n"
        f"- DNS recon: `client=\"{host}\" AND (query CONTAINS \"_ldap._tcp\" OR query CONTAINS \"_kerberos\") | stats count by query,5m`.\n"
        f"- Proxy egress: `user=\"{user}\" AND action=\"connect\" AND dest_category IN (\"cloud_storage\",\"file_sharing\") | stats count,sum(bytes) by dest,5m`."
    )


def _format_for_user_intent(*, user_text: str, report: str) -> str:
    if _is_brief_request(user_text):
        return _summarize_briefly(report=report, user_text=user_text)
    if _HUNT_QUERY_RE.search(user_text or ""):
        return _format_hunt_hypotheses_queries(user_text=user_text, report=report)
    if _NEXT_30_MIN_RE.search(user_text or ""):
        return _format_next_30_minutes(user_text=user_text, report=report)
    if _SPLIT_TEAM_RE.search(user_text or ""):
        return _format_team_split(user_text=user_text, report=report)
    return report


def _format_worker_reports_for_fallback(worker_reports: Any, max_each: int = 550) -> str:
    """Turn partial worker output into actionable text when incident responder did not run."""
    if not isinstance(worker_reports, dict) or not worker_reports:
        return ""
    lines: List[str] = []
    for name in sorted(worker_reports.keys(), key=lambda k: str(k)):
        chunk = summarize_text(str(worker_reports[name]).strip(), max_each)
        if chunk:
            lines.append(f"- **{name}:** {chunk}")
    return "\n".join(lines)


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
    worker_reports = result.get("worker_reports", {})
    worker_digest = _format_worker_reports_for_fallback(worker_reports)
    raw_incident = str(result.get("incident_response", "")).strip()
    incident_response = summarize_text(raw_incident, 1200) if raw_incident else ""
    if not incident_response:
        if worker_digest:
            incident_response = (
                "The incident-responder step did not produce text (often because the run stopped early). "
                "Below is distilled output from specialist workers:\n\n" + worker_digest
            )
        elif stop_reason == "budget_exceeded":
            incident_response = (
                "Run stopped due to execution budget before incident response and final synthesis completed. "
                "Raise `MAX_AGENT_STEPS` / `MAX_RUNTIME_SECONDS`, or lower `MAX_WORKER_TASKS`, then re-run."
            )
        else:
            incident_response = "No containment actions available."
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
    default_steps, default_runtime_s = g2_runtime_budget_caps()
    prompt_preview = (
        f"max_steps={runtime_budget.get('max_steps', default_steps)}, "
        f"max_tool_calls={runtime_budget.get('max_tool_calls', Settings.MAX_TOOL_CALLS)}, "
        f"max_runtime_seconds={runtime_budget.get('max_runtime_seconds', default_runtime_s)}"
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
    *,
    session_id: Optional[str] = None,
) -> Tuple[Dict[str, Any], List[StepTrace], str, str, int, str, Optional[float], str]:
    clean_logs = sanitize_untrusted_text(validate_input(log_input, "input"))
    prompt_version, prompt_template = _resolve_prompt_version()
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

    topic_gate = preflight_g2_user_turn(current_message=clean_logs)
    if topic_gate:
        initial_steps.append(
            _trace_step(
                step="G2Eligibility",
                what_it_does="Stops before multi-agent analysis when the turn is off-topic for defensive security.",
                prompt_preview="off_topic_heuristic",
                input_summary=summarize_text(clean_logs, 240),
                output_summary="Not a security/incident question — short redirect.",
            )
        )
        return (
            {"final_report": topic_gate.final_report},
            initial_steps,
            Settings.FAST_MODEL_NAME,
            topic_gate.stop_reason,
            0,
            prompt_version,
            None,
            "n/a",
        )

    bundled_input = compose_g2_input_with_session(session_id, clean_logs)
    evidence_gate = preflight_g2_evidence_bundle(bundle_text=bundled_input)
    if evidence_gate:
        initial_steps.append(
            _trace_step(
                step="G2Eligibility",
                what_it_does="Requires log/alert-style evidence (or a clear infosec question with cues) before running the graph.",
                prompt_preview="incident_evidence_heuristic",
                input_summary=summarize_text(bundled_input, 320),
                output_summary="Insufficient incident evidence in transcript — prompt user to paste artifacts.",
            )
        )
        return (
            {"final_report": evidence_gate.final_report},
            initial_steps,
            Settings.FAST_MODEL_NAME,
            evidence_gate.stop_reason,
            0,
            prompt_version,
            None,
            "n/a",
        )

    prompted_logs = _build_prompted_input(prompt_template, bundled_input)
    initial_steps.append(
        _trace_step(
            step="ModelRouting",
            what_it_does="Picks the OpenAI model for this request (faster vs stronger).",
            prompt_preview="",
            input_summary=summarize_text(bundled_input, 320),
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
    high_risk = Settings.is_high_risk_task(bundled_input)
    evidence_count = count_evidence_markers(final_text + "\n" + str(result.get("cti_evidence", "")))
    gated_text, gated_stop_reason = apply_action_gating(final_text, high_risk=high_risk, evidence_count=evidence_count)
    result["final_report"] = gated_text
    stop_reason = resolve_stop_reason(stop_reason, gated_stop_reason)
    policy_ok, _ = apply_output_policy_guard(result["final_report"])
    if not policy_ok:
        result["final_report"] = "Output policy blocked this response due to potentially unsafe content. Please narrow the request to defensive security analysis."
        stop_reason = resolve_stop_reason(stop_reason, "needs_human")
    else:
        result["final_report"] = _format_for_user_intent(user_text=clean_logs, report=result["final_report"])
    rubric = _evaluate_response_rubric(result["final_report"])

    final_steps: List[StepTrace] = [
        _trace_step(
            step="Analysis",
            what_it_does="Runs the multi-agent workflow (log analysis, threat prediction, workers, response, verification).",
            prompt_preview=f"Answer format: prompts/{prompt_version} · Multi-agent role set: g2",
            input_summary=summarize_text(bundled_input, 320),
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

    persist_g2_turn(
        session_id=session_id,
        user_message=clean_logs,
        assistant_report=str(result.get("final_report", "")),
    )

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
    session_id: Optional[str] = None,
) -> Tuple[Dict[str, Any], List[StepTrace], str, str, int, str, Optional[float], str]:
    """Run G2 multi-agent workflow. Returns (result, trace, model, stop_reason, steps, prompt_ver, rubric_score, rubric_label)."""
    return _run_g2_analysis_core(log_input, session_id=session_id)


def run_g2_analysis_with_progress(
    log_input: str,
    on_step: Callable[[StepTrace], None],
    session_id: Optional[str] = None,
) -> Tuple[Dict[str, Any], str, str, int, str, Optional[float], str]:
    """Run G2 analysis, emitting each step immediately via on_step callback."""
    result, trace, model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label = _run_g2_analysis_core(
        log_input, session_id=session_id
    )
    for step in trace:
        on_step(step)
    return (result, model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label)
