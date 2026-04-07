"""
Purpose: Node execution logic for G2 multiagent pipeline
What it does:
- Defines per-role node handlers for analysis and response steps
- Runs worker planning, worker tasks, and verification logic
- Normalizes LLM invocation and enriches state with evidence
"""

from __future__ import annotations

import json
from typing import Any, List

from src.agents.g2.multiagent_config import (
    INCIDENT_RESPONDER_ROLE,
    LOG_ANALYZER_ROLE,
    ORCHESTRATOR_ROLE,
    THREAT_PREDICTOR_ROLE,
)
from src.config.settings import Settings
from src.tools.cti_tool import fetch_cti_intelligence
from src.tools.log_parser_tool import parse_system_log
from src.tools.rag_tools import retrieve_security_context
from src.utils.logger import setup_logger
from src.utils.prompt_templates import render_prompt_template
from src.utils.state_validator import REQUIRED_STATE_KEYS, log_state, validate_state
from services.api.agent_loop_runtime import execute_tool_with_runtime_controls

from .state import AgentState

logger = setup_logger(__name__)


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


def _has_usable_tool_evidence(value: str, *, unavailable_markers: tuple[str, ...] = ()) -> bool:
    """Return True when a prior tool result is good enough to reuse safely."""
    content = str(value or "").strip()
    if not content:
        return False
    lowered = content.lower()
    if "returned no usable output" in lowered or "temporarily unavailable" in lowered:
        return False
    return not any(marker in lowered for marker in unavailable_markers)


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


def plan_worker_tasks(state: AgentState) -> List[str]:
    """Create dynamic worker plan based on current evidence."""
    content = (
        f"{state.get('logs', '')}\n{state.get('log_analysis', '')}\n"
        f"{state.get('cti_evidence', '')}\n{state.get('rag_context', '')}"
    ).lower()
    tasks: List[str] = ["baseline_risk_synthesis"]
    if any(k in content for k in ("failed login", "brute", "credential", "auth")):
        tasks.append("identity_containment_plan")
    if any(k in content for k in ("sql", "injection", "xss", "payload", "endpoint")):
        tasks.append("application_hardening_plan")
    if any(k in content for k in ("scan", "ddos", "network", "port")):
        tasks.append("network_detection_plan")
    if any(k in content for k in ("ransomware", "malware", "ioc", "cti")):
        tasks.append("threat_hunt_plan")
    deduped: List[str] = []
    for task in tasks:
        if task not in deduped:
            deduped.append(task)
    return deduped[: max(1, Settings.MAX_WORKER_TASKS)]


def run_worker_task(task_name: str, state: AgentState, llm: Any) -> str:
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
        if _has_usable_tool_evidence(state.get("log_evidence", "")):
            evidence_input = state["log_evidence"]
        else:
            raw_result = execute_tool_with_runtime_controls(
                tool_name="LogParser",
                raw_input=state["logs"],
                tool_func=parse_system_log,
            )
            try:
                parsed = json.loads(raw_result)
                if isinstance(parsed, dict) and "ok" in parsed:
                    evidence_input = (
                        json.dumps(parsed["data"], indent=2)
                        if parsed["ok"] and parsed.get("data")
                        else parsed.get("error", raw_result)
                    )
                else:
                    evidence_input = raw_result
            except (json.JSONDecodeError, TypeError):
                evidence_input = raw_result
    state["log_evidence"] = evidence_input
    state["rag_context"] = (
        state["rag_context"]
        if _has_usable_tool_evidence(
            state.get("rag_context", ""),
            unavailable_markers=("rag disabled", "no relevant context", "unavailable"),
        )
        else (
            execute_tool_with_runtime_controls(
                tool_name="RAGRetriever",
                raw_input=f"log-analysis::{state['logs']}",
                tool_func=retrieve_security_context,
            )
            if Settings.ENABLE_RAG
            else "RAG disabled."
        )
    )
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
    if not _has_usable_tool_evidence(
        state.get("cti_evidence", ""),
        unavailable_markers=("cti unavailable", "unavailable"),
    ) and Settings.OTX_API_KEY:
        raw_cti = execute_tool_with_runtime_controls(
            tool_name="CTIFetch",
            raw_input=cti_query,
            tool_func=fetch_cti_intelligence,
        )
        try:
            parsed = json.loads(raw_cti)
            if isinstance(parsed, dict) and "ok" in parsed:
                state["cti_evidence"] = (
                    parsed.get("data", raw_cti) if parsed["ok"] else parsed.get("error", raw_cti)
                )
            else:
                state["cti_evidence"] = raw_cti
        except (json.JSONDecodeError, TypeError):
            state["cti_evidence"] = raw_cti
    elif not _has_usable_tool_evidence(
        state.get("cti_evidence", ""),
        unavailable_markers=("cti unavailable", "unavailable"),
    ):
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
