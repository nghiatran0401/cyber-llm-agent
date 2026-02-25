"""LangGraph workflow builder for the G2 multiagent pipeline."""

from __future__ import annotations

from typing import Any

from langchain_openai import ChatOpenAI

from src.config.settings import Settings
from src.utils.logger import setup_logger

from .nodes import (
    incident_responder_node,
    log_analyzer_node,
    orchestrator_node,
    threat_predictor_node,
)
from .state import AgentState

logger = setup_logger(__name__)


def _default_llm() -> ChatOpenAI:
    """Construct the default ChatOpenAI LLM from settings."""
    Settings.validate()
    return ChatOpenAI(
        model=Settings.FAST_MODEL_NAME,
        temperature=Settings.TEMPERATURE,
        openai_api_key=Settings.OPENAI_API_KEY,
    )


def _build_langgraph_workflow(llm: Any):
    """Build and compile the LangGraph state graph."""
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
    """Create and return a compiled LangGraph multiagent workflow."""
    selected_llm = llm or _default_llm()
    logger.info("Creating multiagent workflow.")
    return _build_langgraph_workflow(selected_llm)
