"""
Purpose: Build and compile the G2 LangGraph workflow
What it does:
- Creates a default LLM instance from project settings
- Executes core G2 nodes via minimal LangGraph wrappers
"""

from __future__ import annotations

from typing import Any, Callable

from langchain_openai import ChatOpenAI
from langgraph.graph import END, StateGraph

from src.config.settings import Settings
from src.utils.logger import setup_logger

from .nodes import incident_responder_node, log_analyzer_node, orchestrator_node, threat_predictor_node
from .state import AgentState

logger = setup_logger(__name__)
_CORE_NODE_HANDLERS: dict[str, Callable[[AgentState, Any], AgentState]] = {
    "log_analyzer": log_analyzer_node,
    "threat_predictor": threat_predictor_node,
    "incident_responder": incident_responder_node,
    "orchestrator": orchestrator_node,
}


def _default_llm() -> ChatOpenAI:
    """Construct the default ChatOpenAI LLM from settings."""
    Settings.validate()
    return ChatOpenAI(
        model=Settings.FAST_MODEL_NAME,
        temperature=Settings.TEMPERATURE,
        openai_api_key=Settings.OPENAI_API_KEY,
    )


def run_core_node_with_langgraph(
    *,
    node_name: str,
    state: AgentState,
    llm: Any | None = None,
) -> AgentState:
    if node_name not in _CORE_NODE_HANDLERS:
        raise ValueError(f"Unsupported core node '{node_name}'.")

    selected_llm = llm or _default_llm()
    workflow = StateGraph(AgentState)
    handler = _CORE_NODE_HANDLERS[node_name]
    workflow.add_node(node_name, lambda current_state: handler(current_state, selected_llm))
    workflow.set_entry_point(node_name)
    workflow.add_edge(node_name, END)
    compiled = workflow.compile()
    return compiled.invoke(state)
