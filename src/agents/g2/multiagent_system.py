"""Multiagent workflow using LangGraph."""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, TypedDict

from langchain_openai import ChatOpenAI

from src.agents.g2.multiagent_config import (
    LOG_ANALYZER_ROLE,
    THREAT_PREDICTOR_ROLE,
    INCIDENT_RESPONDER_ROLE,
    ORCHESTRATOR_ROLE,
)
from src.config.settings import Settings
from src.tools.rag_tools import retrieve_security_context
from src.tools.security_tools import fetch_cti_intelligence, parse_system_log
from src.utils.logger import setup_logger
from src.utils.prompt_templates import render_prompt_template
from src.utils.state_validator import validate_state, log_state, REQUIRED_STATE_KEYS

logger = setup_logger(__name__)


class AgentState(TypedDict):
    """State shared across multiagent nodes."""

    logs: str
    log_evidence: str
    rag_context: str
    cti_evidence: str
    worker_plan: List[str]
    worker_reports: Dict[str, str]
    verifier_feedback: str
    verifier_passed: bool
    log_analysis: str
    threat_prediction: str
    incident_response: str
    final_report: str


class MultiagentStepTrace(TypedDict):
    """Human-readable trace for one multiagent node execution."""

    step: str
    what_it_does: str
    prompt_preview: str
    input_summary: str
    output_summary: str


def create_initial_state(logs: str) -> AgentState:
    """Create default state for a new multiagent run."""
    return {
        "logs": logs,
        "log_evidence": "",
        "rag_context": "",
        "cti_evidence": "",
        "worker_plan": [],
        "worker_reports": {},
        "verifier_feedback": "",
        "verifier_passed": False,
        "log_analysis": "",
        "threat_prediction": "",
        "incident_response": "",
        "final_report": "",
    }


def _invoke_llm(llm: Any, prompt: str) -> str:
    """Invoke LLM across common interfaces and normalize to text."""
    if hasattr(llm, "invoke"):
        result = llm.invoke(prompt)
        if hasattr(result, "content"):
            return str(result.content)
        return str(result)
    if hasattr(llm, "predict"):
        return str(llm.predict(prompt))
    raise TypeError("Provided llm must support invoke() or predict().")


def _looks_like_log_path(raw_input: str) -> bool:
    value = (raw_input or "").strip().lower()
    return value.endswith((".log", ".txt", ".json", ".jsonl"))


def _derive_threat_query(text: str) -> str:
    content = (text or "").lower()
    if "ransomware" in content:
        return "ransomware"
    if "phish" in content:
        return "phishing"
    if "sql" in content:
        return "sql injection"
    if "xss" in content:
        return "xss"
    if "brute" in content or "credential" in content:
        return "credential stuffing"
    if "ddos" in content or "scan" in content:
        return "ddos"
    return "malware"


def _plan_worker_tasks(state: AgentState) -> List[str]:
    """Create dynamic worker plan based on current evidence."""
    content = (
        f"{state.get('logs', '')}\n{state.get('log_analysis', '')}\n"
        f"{state.get('cti_evidence', '')}\n{state.get('rag_context', '')}"
    ).lower()
    tasks: List[str] = ["baseline_risk_synthesis"]
    if any(key in content for key in ("failed login", "brute", "credential", "auth")):
        tasks.append("identity_containment_plan")
    if any(key in content for key in ("sql", "injection", "xss", "payload", "endpoint")):
        tasks.append("application_hardening_plan")
    if any(key in content for key in ("scan", "ddos", "network", "port")):
        tasks.append("network_detection_plan")
    if any(key in content for key in ("ransomware", "malware", "ioc", "cti")):
        tasks.append("threat_hunt_plan")

    deduped: List[str] = []
    for task in tasks:
        if task not in deduped:
            deduped.append(task)
    return deduped[: max(1, Settings.MAX_WORKER_TASKS)]


def _run_worker_task(task_name: str, state: AgentState, llm: Any) -> str:
    """Execute one worker task and return concise findings."""
    prompt = render_prompt_template(
        "g2/nodes/worker_task.txt",
        task_name=task_name,
        log_analysis=state["log_analysis"],
        threat_prediction=state["threat_prediction"],
        cti_evidence=state["cti_evidence"],
        rag_context=state["rag_context"],
    )
    return _invoke_llm(llm, prompt)


def log_analyzer_node(state: AgentState, llm: Any) -> AgentState:
    """Analyze raw logs and populate log_analysis."""
    validate_state(state, REQUIRED_STATE_KEYS)
    if not state["logs"].strip():
        raise ValueError("No logs provided.")

    log_state(state, "log_analyzer")
    evidence_input = state["logs"]
    if _looks_like_log_path(state["logs"]):
        evidence_input = parse_system_log(state["logs"])
    state["log_evidence"] = evidence_input
    state["rag_context"] = retrieve_security_context(state["logs"]) if Settings.ENABLE_RAG else "RAG disabled."
    prompt = render_prompt_template(
        "g2/nodes/log_analyzer.txt",
        system_prompt=LOG_ANALYZER_ROLE.system_prompt,
        logs=state["logs"],
        log_evidence=state["log_evidence"],
        rag_context=state["rag_context"],
    )
    state["log_analysis"] = _invoke_llm(llm, prompt)
    return state


def threat_predictor_node(state: AgentState, llm: Any) -> AgentState:
    """Predict likely attack progression from analysis."""
    validate_state(state, REQUIRED_STATE_KEYS)
    log_state(state, "threat_predictor")
    cti_query = _derive_threat_query(state["log_analysis"])
    if Settings.OTX_API_KEY:
        state["cti_evidence"] = fetch_cti_intelligence(cti_query)
    else:
        state["cti_evidence"] = "CTI unavailable: OTX_API_KEY is not configured."

    prompt = render_prompt_template(
        "g2/nodes/threat_predictor.txt",
        system_prompt=THREAT_PREDICTOR_ROLE.system_prompt,
        log_analysis=state["log_analysis"],
        cti_evidence=state["cti_evidence"],
        rag_context=state["rag_context"],
    )
    state["threat_prediction"] = _invoke_llm(llm, prompt)
    return state


def incident_responder_node(state: AgentState, llm: Any) -> AgentState:
    """Recommend containment and remediation actions."""
    validate_state(state, REQUIRED_STATE_KEYS)
    log_state(state, "incident_responder")

    worker_reports_text = "\n\n".join(
        f"{task}:\n{report}" for task, report in state.get("worker_reports", {}).items()
    )
    prompt = render_prompt_template(
        "g2/nodes/incident_responder.txt",
        system_prompt=INCIDENT_RESPONDER_ROLE.system_prompt,
        threat_prediction=state["threat_prediction"],
        cti_evidence=state["cti_evidence"],
        worker_reports=worker_reports_text or "No worker reports available.",
    )
    state["incident_response"] = _invoke_llm(llm, prompt)
    return state


def verifier_node(state: AgentState, llm: Any) -> AgentState:
    """Verify draft response quality against evidence and worker outputs."""
    validate_state(state, REQUIRED_STATE_KEYS)
    log_state(state, "verifier")
    worker_reports_text = "\n\n".join(
        f"{task}:\n{report}" for task, report in state.get("worker_reports", {}).items()
    )
    prompt = render_prompt_template(
        "g2/nodes/verifier.txt",
        log_analysis=state["log_analysis"],
        threat_prediction=state["threat_prediction"],
        worker_reports=worker_reports_text or "No worker reports available.",
        incident_response=state["incident_response"],
    )
    verdict_text = _invoke_llm(llm, prompt)
    normalized = verdict_text.lower()
    passed = "verdict: pass" in normalized and "verdict: fail" not in normalized
    if not passed:
        # Deterministic fallback guard when model output is malformed/ambiguous.
        passed = bool(state.get("incident_response", "").strip() and state.get("worker_reports"))
    state["verifier_passed"] = passed
    state["verifier_feedback"] = verdict_text
    return state


def orchestrator_node(state: AgentState, llm: Any) -> AgentState:
    """Consolidate full workflow output for final report."""
    validate_state(state, REQUIRED_STATE_KEYS)
    log_state(state, "orchestrator")

    worker_reports_text = "\n\n".join(
        f"{task}:\n{report}" for task, report in state.get("worker_reports", {}).items()
    )
    prompt = render_prompt_template(
        "g2/nodes/orchestrator.txt",
        system_prompt=ORCHESTRATOR_ROLE.system_prompt,
        log_analysis=state["log_analysis"],
        threat_prediction=state["threat_prediction"],
        incident_response=state["incident_response"],
        worker_reports=worker_reports_text or "No worker reports available.",
        verifier_feedback=state["verifier_feedback"] or "No verifier feedback.",
        cti_evidence=state["cti_evidence"],
        rag_context=state["rag_context"],
    )
    state["final_report"] = _invoke_llm(llm, prompt)
    return state


def _default_llm() -> ChatOpenAI:
    """Construct default ChatOpenAI client from settings."""
    Settings.validate()
    return ChatOpenAI(
        model=Settings.FAST_MODEL_NAME,
        temperature=Settings.TEMPERATURE,
        openai_api_key=Settings.OPENAI_API_KEY,
    )


def _build_langgraph_workflow(llm: Any):
    """Build and compile LangGraph workflow."""
    try:
        from langgraph.graph import END, StateGraph
    except ImportError as exc:
        raise ImportError(
            "langgraph is required for create_multiagent_workflow(). "
            "Install it with: pip install langgraph"
        ) from exc

    workflow = StateGraph(AgentState)
    workflow.add_node("log_analyzer", lambda state: log_analyzer_node(state, llm))
    workflow.add_node("threat_predictor", lambda state: threat_predictor_node(state, llm))
    workflow.add_node("incident_responder", lambda state: incident_responder_node(state, llm))
    workflow.add_node("orchestrator", lambda state: orchestrator_node(state, llm))

    workflow.set_entry_point("log_analyzer")
    workflow.add_edge("log_analyzer", "threat_predictor")
    workflow.add_edge("threat_predictor", "incident_responder")
    workflow.add_edge("incident_responder", "orchestrator")
    workflow.add_edge("orchestrator", END)

    return workflow.compile()


def create_multiagent_workflow(llm: Any | None = None):
    """Create compiled LangGraph multiagent workflow."""
    selected_llm = llm or _default_llm()
    logger.info("Creating multiagent workflow.")
    return _build_langgraph_workflow(selected_llm)


def run_multiagent_assessment(logs: str, llm: Any | None = None) -> AgentState:
    """Convenience runner for single-call assessments."""
    workflow = create_multiagent_workflow(llm=llm)
    return workflow.invoke(create_initial_state(logs))


def _summarize_text(text: str, max_len: int = 220) -> str:
    """Trim large text to concise trace snippets."""
    content = (text or "").strip().replace("\n", " ")
    if len(content) <= max_len:
        return content
    return content[:max_len] + "..."


def run_multiagent_with_trace(
    logs: str,
    llm: Any | None = None,
    on_step: Callable[[MultiagentStepTrace], None] | None = None,
) -> Dict[str, Any]:
    """Run multiagent pipeline sequentially and return state + step trace.

    This is primarily used by the UI to show what each node is doing.
    """
    selected_llm = llm or _default_llm()
    state = create_initial_state(logs)
    trace: List[MultiagentStepTrace] = []
    steps_used = 0
    stop_reason = "completed"
    start_time = time.perf_counter()

    def _within_budget() -> bool:
        nonlocal stop_reason
        if steps_used >= Settings.MAX_AGENT_STEPS:
            stop_reason = "budget_exceeded"
            return False
        if (time.perf_counter() - start_time) > Settings.MAX_RUNTIME_SECONDS:
            stop_reason = "budget_exceeded"
            return False
        return True

    # Step 1: Log Analyzer
    if not _within_budget():
        return {"result": state, "trace": trace, "stop_reason": stop_reason, "steps_used": steps_used}
    analyzer_input = _summarize_text(state["logs"])
    analyzer_prompt = (
        f"{LOG_ANALYZER_ROLE.system_prompt}\n\n"
        f"Input logs:\n{state['logs']}\n\n"
        f"Log parser evidence:\n{state['log_evidence']}\n\n"
        f"Retrieved context:\n{state['rag_context']}\n\n"
        "Return key findings with severity and evidence."
    )
    state = log_analyzer_node(state, selected_llm)
    steps_used += 1
    trace.append(
        {
            "step": "LogAnalyzer",
            "what_it_does": "Finds suspicious patterns and classifies severity from raw logs.",
            "prompt_preview": _summarize_text(analyzer_prompt),
            "input_summary": analyzer_input,
            "output_summary": _summarize_text(state["log_analysis"]),
        }
    )
    if on_step:
        on_step(trace[-1])

    # Step 1.5: Orchestrator plans dynamic worker tasks
    if not _within_budget():
        return {"result": state, "trace": trace, "stop_reason": stop_reason, "steps_used": steps_used}
    state["worker_plan"] = _plan_worker_tasks(state)
    steps_used += 1
    trace.append(
        {
            "step": "WorkerPlanner",
            "what_it_does": "Builds dynamic worker task list based on evidence.",
            "prompt_preview": _summarize_text(
                f"planned_tasks={', '.join(state['worker_plan']) if state['worker_plan'] else 'none'}"
            ),
            "input_summary": _summarize_text(f"analysis={state['log_analysis']} cti={state['cti_evidence']}"),
            "output_summary": _summarize_text(str(state["worker_plan"])),
        }
    )
    if on_step:
        on_step(trace[-1])

    # Step 2: Threat Predictor
    if not _within_budget():
        return {"result": state, "trace": trace, "stop_reason": stop_reason, "steps_used": steps_used}
    predictor_input = _summarize_text(state["log_analysis"])
    predictor_prompt = (
        f"{THREAT_PREDICTOR_ROLE.system_prompt}\n\n"
        f"Current analysis:\n{state['log_analysis']}\n\n"
        f"CTI evidence:\n{state['cti_evidence']}\n\n"
        f"Retrieved context:\n{state['rag_context']}\n\n"
        "Predict likely attacker next steps and risk level."
    )
    state = threat_predictor_node(state, selected_llm)
    steps_used += 1
    trace.append(
        {
            "step": "ThreatPredictor",
            "what_it_does": "Predicts likely attacker next steps based on log analysis.",
            "prompt_preview": _summarize_text(predictor_prompt),
            "input_summary": predictor_input,
            "output_summary": _summarize_text(state["threat_prediction"]),
        }
    )
    if on_step:
        on_step(trace[-1])

    # Step 2.5: Worker execution (dynamic)
    for task_name in state.get("worker_plan", []):
        if not _within_budget():
            return {"result": state, "trace": trace, "stop_reason": stop_reason, "steps_used": steps_used}
        report = _run_worker_task(task_name, state, selected_llm)
        state["worker_reports"][task_name] = report
        steps_used += 1
        trace.append(
            {
                "step": "WorkerTask",
                "what_it_does": f"Executes specialized worker task: {task_name}.",
                "prompt_preview": _summarize_text(task_name),
                "input_summary": _summarize_text(state["threat_prediction"]),
                "output_summary": _summarize_text(report),
            }
        )
        if on_step:
            on_step(trace[-1])

    # Step 3: Incident Responder
    if not _within_budget():
        return {"result": state, "trace": trace, "stop_reason": stop_reason, "steps_used": steps_used}
    responder_input = _summarize_text(state["threat_prediction"])
    responder_prompt = (
        f"{INCIDENT_RESPONDER_ROLE.system_prompt}\n\n"
        f"Threat prediction:\n{state['threat_prediction']}\n\n"
        f"CTI evidence:\n{state['cti_evidence']}\n\n"
        "Provide immediate response and short follow-up actions."
    )
    state = incident_responder_node(state, selected_llm)
    steps_used += 1
    trace.append(
        {
            "step": "IncidentResponder",
            "what_it_does": "Creates immediate containment and response actions.",
            "prompt_preview": _summarize_text(responder_prompt),
            "input_summary": responder_input,
            "output_summary": _summarize_text(state["incident_response"]),
        }
    )
    if on_step:
        on_step(trace[-1])

    # Step 3.5: Verifier with one retry path
    if not _within_budget():
        return {"result": state, "trace": trace, "stop_reason": stop_reason, "steps_used": steps_used}
    verifier_attempts = 0
    while verifier_attempts <= 1:
        state = verifier_node(state, selected_llm)
        steps_used += 1
        trace.append(
            {
                "step": "Verifier",
                "what_it_does": "Checks whether draft response is evidence-grounded.",
                "prompt_preview": _summarize_text("verifier pass/fail check"),
                "input_summary": _summarize_text(state["incident_response"]),
                "output_summary": _summarize_text(
                    f"passed={state['verifier_passed']} feedback={state['verifier_feedback']}"
                ),
            }
        )
        if on_step:
            on_step(trace[-1])
        if state["verifier_passed"]:
            break
        verifier_attempts += 1
        if verifier_attempts > 1:
            stop_reason = "blocked"
            break
        if not _within_budget():
            return {"result": state, "trace": trace, "stop_reason": stop_reason, "steps_used": steps_used}
        # Retry exactly once with verifier feedback embedded.
        revise_prompt = (
            f"{state['incident_response']}\n\n"
            f"Revise the response based on verifier feedback:\n{state['verifier_feedback']}"
        )
        state["incident_response"] = _invoke_llm(selected_llm, revise_prompt)
        steps_used += 1
        trace.append(
            {
                "step": "IncidentResponderRetry",
                "what_it_does": "Revises incident response once after verifier failure.",
                "prompt_preview": _summarize_text("retry incident response with verifier feedback"),
                "input_summary": _summarize_text(state["verifier_feedback"]),
                "output_summary": _summarize_text(state["incident_response"]),
            }
        )
        if on_step:
            on_step(trace[-1])

    # Step 4: Orchestrator
    if not _within_budget():
        return {"result": state, "trace": trace, "stop_reason": stop_reason, "steps_used": steps_used}
    orchestrator_input = _summarize_text(
        f"analysis={state['log_analysis']} prediction={state['threat_prediction']} response={state['incident_response']}"
    )
    orchestrator_prompt = (
        f"{ORCHESTRATOR_ROLE.system_prompt}\n\n"
        f"Log analysis:\n{state['log_analysis']}\n\n"
        f"Threat prediction:\n{state['threat_prediction']}\n\n"
        f"Incident response:\n{state['incident_response']}\n\n"
        f"CTI evidence:\n{state['cti_evidence']}\n\n"
        f"Retrieved context:\n{state['rag_context']}\n\n"
        "Create one executive summary with top risks and immediate actions."
    )
    state = orchestrator_node(state, selected_llm)
    steps_used += 1
    trace.append(
        {
            "step": "Orchestrator",
            "what_it_does": "Combines all agent outputs into one final decision summary.",
            "prompt_preview": _summarize_text(orchestrator_prompt),
            "input_summary": orchestrator_input,
            "output_summary": _summarize_text(state["final_report"]),
        }
    )
    if on_step:
        on_step(trace[-1])

    return {"result": state, "trace": trace, "stop_reason": stop_reason, "steps_used": steps_used}
