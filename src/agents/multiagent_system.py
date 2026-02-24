"""Week 6 multiagent workflow using LangGraph."""

from __future__ import annotations

from typing import Any, Callable, Dict, TypedDict

from langchain_openai import ChatOpenAI

from src.agents.multiagent_config import (
    LOG_ANALYZER_ROLE,
    THREAT_PREDICTOR_ROLE,
    INCIDENT_RESPONDER_ROLE,
    ORCHESTRATOR_ROLE,
)
from src.config.settings import Settings
from src.utils.logger import setup_logger
from src.utils.state_validator import validate_state, log_state, REQUIRED_STATE_KEYS

logger = setup_logger(__name__)


class AgentState(TypedDict):
    """State shared across multiagent nodes."""

    logs: str
    log_analysis: str
    threat_prediction: str
    incident_response: str
    final_report: str


def create_initial_state(logs: str) -> AgentState:
    """Create default state for a new multiagent run."""
    return {
        "logs": logs,
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


def log_analyzer_node(state: AgentState, llm: Any) -> AgentState:
    """Analyze raw logs and populate log_analysis."""
    validate_state(state, REQUIRED_STATE_KEYS)
    if not state["logs"].strip():
        raise ValueError("No logs provided.")

    log_state(state, "log_analyzer")
    prompt = (
        f"{LOG_ANALYZER_ROLE.system_prompt}\n\n"
        f"Input logs:\n{state['logs']}\n\n"
        "Return key findings with severity and evidence."
    )
    state["log_analysis"] = _invoke_llm(llm, prompt)
    return state


def threat_predictor_node(state: AgentState, llm: Any) -> AgentState:
    """Predict likely attack progression from analysis."""
    validate_state(state, REQUIRED_STATE_KEYS)
    log_state(state, "threat_predictor")

    prompt = (
        f"{THREAT_PREDICTOR_ROLE.system_prompt}\n\n"
        f"Current analysis:\n{state['log_analysis']}\n\n"
        "Predict likely attacker next steps and risk level."
    )
    state["threat_prediction"] = _invoke_llm(llm, prompt)
    return state


def incident_responder_node(state: AgentState, llm: Any) -> AgentState:
    """Recommend containment and remediation actions."""
    validate_state(state, REQUIRED_STATE_KEYS)
    log_state(state, "incident_responder")

    prompt = (
        f"{INCIDENT_RESPONDER_ROLE.system_prompt}\n\n"
        f"Threat prediction:\n{state['threat_prediction']}\n\n"
        "Provide immediate response and short follow-up actions."
    )
    state["incident_response"] = _invoke_llm(llm, prompt)
    return state


def orchestrator_node(state: AgentState, llm: Any) -> AgentState:
    """Consolidate full workflow output for final report."""
    validate_state(state, REQUIRED_STATE_KEYS)
    log_state(state, "orchestrator")

    prompt = (
        f"{ORCHESTRATOR_ROLE.system_prompt}\n\n"
        f"Log analysis:\n{state['log_analysis']}\n\n"
        f"Threat prediction:\n{state['threat_prediction']}\n\n"
        f"Incident response:\n{state['incident_response']}\n\n"
        "Create one executive summary with top risks and immediate actions."
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

