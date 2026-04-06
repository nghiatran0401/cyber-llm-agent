"""
Purpose: Runtime entry points for G2 multiagent execution
What it does:
- Exposes a one-call assessment helper for the workflow
- Runs a traced sequential execution for UI step visibility
- Enforces runtime and step budgets with stop reasons
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List

from src.agents.g2.multiagent_config import (
    INCIDENT_RESPONDER_ROLE,
    LOG_ANALYZER_ROLE,
    ORCHESTRATOR_ROLE,
    THREAT_PREDICTOR_ROLE,
)
from src.config.settings import Settings
from src.utils.logger import setup_logger
from services.api.agent_loop_runtime import (
    activate_runtime_budget,
    create_runtime_budget_state,
    deactivate_runtime_budget,
    resolve_stop_reason,
    sync_runtime_budget_steps,
)

from .graph import _default_llm
from .nodes import (
    incident_responder_node,
    log_analyzer_node,
    orchestrator_node,
    plan_worker_tasks,
    run_worker_task,
    verifier_node,
    threat_predictor_node,
    _invoke_llm,
)
from .state import AgentState, MultiagentStepTrace, create_initial_state

logger = setup_logger(__name__)


def _summarize_text(text: str, max_len: int = 220) -> str:
    content = (text or "").strip().replace("\n", " ")
    if len(content) <= max_len:
        return content
    return content[:max_len] + "..."


def run_multiagent_assessment(logs: str, llm: Any | None = None) -> AgentState:
    """Convenience runner for single-call assessments."""
    from .graph import create_multiagent_workflow
    workflow = create_multiagent_workflow(llm=llm)
    return workflow.invoke(create_initial_state(logs))


def run_multiagent_with_trace(
    logs: str,
    llm: Any | None = None,
    on_step: Callable[[MultiagentStepTrace], None] | None = None,
) -> Dict[str, Any]:
    """Run multiagent pipeline sequentially and return state + step trace.

    Used by the UI to show what each node is doing as it executes.
    """
    selected_llm = llm or _default_llm()
    state = create_initial_state(logs)
    trace: List[MultiagentStepTrace] = []
    steps_used = 0
    stop_reason = "completed"
    budget_state = create_runtime_budget_state(
        max_steps=Settings.MAX_AGENT_STEPS,
        max_tool_calls=Settings.MAX_TOOL_CALLS,
        max_runtime_seconds=Settings.MAX_RUNTIME_SECONDS,
    )
    budget_token = activate_runtime_budget(budget_state)

    try:
        def _result_payload() -> Dict[str, Any]:
            """Return one consistent payload shape for all exit paths."""
            return {
                "result": state,
                "trace": trace,
                "stop_reason": stop_reason,
                "steps_used": steps_used,
            }

        def _within_budget() -> bool:
            """Check shared runtime limits before the next major execution step."""
            nonlocal stop_reason
            budget_stop_reason = sync_runtime_budget_steps(steps_used)
            stop_reason = resolve_stop_reason(stop_reason, budget_stop_reason)
            return stop_reason != "budget_exceeded"

        def _sync_after_step() -> bool:
            """Refresh stop reason after a step because tools may have exhausted the budget mid-step."""
            nonlocal stop_reason
            budget_stop_reason = sync_runtime_budget_steps(steps_used)
            stop_reason = resolve_stop_reason(stop_reason, budget_stop_reason)
            return stop_reason != "budget_exceeded"

        def _emit(entry: MultiagentStepTrace) -> None:
            trace.append(entry)
            if on_step:
                on_step(entry)

        # Step 1: Log Analyzer
        if not _within_budget():
            return _result_payload()
        state = log_analyzer_node(state, selected_llm)
        steps_used += 1
        _emit({"step": "LogAnalyzer", "what_it_does": "Finds suspicious patterns and classifies severity from raw logs.",
               "prompt_preview": _summarize_text(f"{LOG_ANALYZER_ROLE.system_prompt} logs={state['logs']}"),
               "input_summary": _summarize_text(state["logs"]), "output_summary": _summarize_text(state["log_analysis"])})
        if not _sync_after_step():
            return _result_payload()

        # Step 1.5: Worker planner
        if not _within_budget():
            return _result_payload()
        state["worker_plan"] = plan_worker_tasks(state)
        steps_used += 1
        _emit({"step": "WorkerPlanner", "what_it_does": "Builds dynamic worker task list based on evidence.",
               "prompt_preview": _summarize_text(f"planned_tasks={', '.join(state['worker_plan'])}"),
               "input_summary": _summarize_text(f"analysis={state['log_analysis']}"),
               "output_summary": _summarize_text(str(state["worker_plan"]))})
        if not _sync_after_step():
            return _result_payload()

        # Step 2: Threat Predictor
        if not _within_budget():
            return _result_payload()
        state = threat_predictor_node(state, selected_llm)
        steps_used += 1
        _emit({"step": "ThreatPredictor", "what_it_does": "Predicts likely attacker next steps based on log analysis.",
               "prompt_preview": _summarize_text(f"{THREAT_PREDICTOR_ROLE.system_prompt}"),
               "input_summary": _summarize_text(state["log_analysis"]), "output_summary": _summarize_text(state["threat_prediction"])})
        if not _sync_after_step():
            return _result_payload()

        # Step 2.5: Worker execution (dynamic)
        for task_name in state.get("worker_plan", []):
            if not _within_budget():
                return _result_payload()
            report = run_worker_task(task_name, state, selected_llm)
            state["worker_reports"][task_name] = report
            steps_used += 1
            _emit({"step": "WorkerTask", "what_it_does": f"Executes specialized worker task: {task_name}.",
                   "prompt_preview": _summarize_text(task_name), "input_summary": _summarize_text(state["threat_prediction"]),
                   "output_summary": _summarize_text(report)})
            if not _sync_after_step():
                return _result_payload()

        # Step 3: Incident Responder
        if not _within_budget():
            return _result_payload()
        state = incident_responder_node(state, selected_llm)
        steps_used += 1
        _emit({"step": "IncidentResponder", "what_it_does": "Creates immediate containment and response actions.",
               "prompt_preview": _summarize_text(f"{INCIDENT_RESPONDER_ROLE.system_prompt}"),
               "input_summary": _summarize_text(state["threat_prediction"]), "output_summary": _summarize_text(state["incident_response"])})
        if not _sync_after_step():
            return _result_payload()

        # Step 3.5: Verifier with one retry
        if not _within_budget():
            return _result_payload()
        verifier_attempts = 0
        while verifier_attempts <= 1:
            state = verifier_node(state, selected_llm)
            steps_used += 1
            _emit({"step": "Verifier", "what_it_does": "Checks whether draft response is evidence-grounded.",
                   "prompt_preview": "verifier pass/fail check",
                   "input_summary": _summarize_text(state["incident_response"]),
                   "output_summary": _summarize_text(f"passed={state['verifier_passed']} feedback={state['verifier_feedback']}")})
            if not _sync_after_step():
                return _result_payload()
            if state["verifier_passed"]:
                break
            verifier_attempts += 1
            if verifier_attempts > 1:
                stop_reason = "blocked"
                break
            if not _within_budget():
                return _result_payload()
            revise_prompt = f"{state['incident_response']}\n\nRevise based on verifier feedback:\n{state['verifier_feedback']}"
            state["incident_response"] = _invoke_llm(selected_llm, revise_prompt)
            steps_used += 1
            _emit({"step": "IncidentResponderRetry", "what_it_does": "Revises incident response once after verifier failure.",
                   "prompt_preview": "retry with verifier feedback",
                   "input_summary": _summarize_text(state["verifier_feedback"]),
                   "output_summary": _summarize_text(state["incident_response"])})
            if not _sync_after_step():
                return _result_payload()

        # Step 4: Orchestrator
        if not _within_budget():
            return _result_payload()
        state = orchestrator_node(state, selected_llm)
        steps_used += 1
        _emit({"step": "Orchestrator", "what_it_does": "Combines all agent outputs into one final decision summary.",
               "prompt_preview": _summarize_text(f"{ORCHESTRATOR_ROLE.system_prompt}"),
               "input_summary": _summarize_text(f"analysis={state['log_analysis']} prediction={state['threat_prediction']}"),
               "output_summary": _summarize_text(state["final_report"])})
        _sync_after_step()
        return _result_payload()
    finally:
        state["runtime_budget"] = {
            "steps_used": budget_state.steps_used,
            "tool_calls_used": budget_state.tool_calls_used,
            "duplicate_tool_calls": budget_state.duplicate_tool_calls,
            "semantic_duplicate_tool_calls": budget_state.semantic_duplicate_tool_calls,
            "cached_tool_reuses": budget_state.cached_tool_reuses,
            "cooldown_skips": budget_state.cooldown_skips,
            "tool_failures": budget_state.tool_failures,
            "max_steps": budget_state.max_steps,
            "max_tool_calls": budget_state.max_tool_calls,
            "max_runtime_seconds": budget_state.max_runtime_seconds,
        }
        deactivate_runtime_budget(budget_token)
