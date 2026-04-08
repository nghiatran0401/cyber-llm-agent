"""
G1 single-agent: LangChain tool loop, fast/strong model routing, session-backed memory.
"""

from __future__ import annotations

from typing import Any, Optional
from uuid import uuid4

from langchain.agents import create_agent
from langchain_openai import ChatOpenAI

from src.agents.g1.llm_payload import extract_response_text, extract_user_text
from src.agents.shared.intent_routing import is_high_risk_intent
from src.config.settings import Settings
from src.tools.cti_tool import cti_fetch
from src.tools.log_parser_tool import log_parser
from src.tools.rag_tools import rag_retriever
from src.utils.logger import setup_logger
from src.utils.memory_manager import ConversationMemory
from src.utils.prompt_templates import load_prompt_template
from src.utils.session_manager import SessionManager

logger = setup_logger(__name__)


def _create_tool_agent(model_name: str, verbose: bool = True) -> Any:
    """One LangChain agent: ChatOpenAI + log/CTI/RAG tools + G1 system prompt."""
    llm = ChatOpenAI(
        model=model_name,
        temperature=Settings.TEMPERATURE,
        openai_api_key=Settings.OPENAI_API_KEY,
    )
    tools = [log_parser, cti_fetch, rag_retriever]
    return create_agent(
        model=llm,
        tools=tools,
        system_prompt=load_prompt_template("g1/system_prompt.txt"),
        debug=verbose,
    )


class _AdaptiveSecurityAgent:
    """Picks fast vs strong underlying agent using ``is_high_risk_intent`` on routing text."""

    def __init__(self, verbose: bool = True) -> None:
        self.verbose = verbose
        self.fast_model = Settings.FAST_MODEL_NAME
        self.strong_model = Settings.STRONG_MODEL_NAME
        self.fast_agent = _create_tool_agent(self.fast_model, verbose=verbose)
        self.strong_agent = _create_tool_agent(self.strong_model, verbose=verbose)

    def invoke(self, payload: Any, *, routing_text: Optional[str] = None) -> Any:
        user_text = routing_text if routing_text is not None else extract_user_text(payload)
        selected = self.strong_agent if is_high_risk_intent(user_text) else self.fast_agent
        return selected.invoke(payload)


def _restore_memory_from_session(
    memory: ConversationMemory,
    session_manager: SessionManager,
    session_id: str,
) -> None:
    """Restore the memory from the session."""
    existing = session_manager.load_session(session_id)
    if not existing:
        return
    memory.load_state(
        messages=existing.get("messages", []),
        running_summary=existing.get("running_summary", ""),
        episodic_memories=existing.get("episodic_memories", []),
        semantic_facts=existing.get("semantic_facts", []),
    )

def _build_g1_user_message_with_memory(
    *,
    agent_input: str,
    recall_query: str,
    memory: ConversationMemory,
) -> tuple[str, int]:
    context_block = memory.render_context(query=recall_query)

    message = f"Use this conversation context as background. Answer the current user request directly; do not repeat a full prior incident write-up unless they ask for a recap or new assessment.\n\n{context_block}\n\nCurrent user request:\n{agent_input}"

    return message, len(context_block)
    

def _invoke_backend(
    backend: Any,
    *,
    user_message: str,
    routing_text: str,
) -> Any:
    """Invoke the backend agent."""
    payload = {"messages": [("user", user_message)]}
    if isinstance(backend, _AdaptiveSecurityAgent):
        return backend.invoke(payload, routing_text=routing_text)
    return backend.invoke(payload)


class G1Agent:
    def __init__(
        self,
        *,
        session_id: Optional[str] = None,
        backend_agent: Optional[Any] = None,
        verbose: bool = True,
        memory: Optional[ConversationMemory] = None,
    ) -> None:
        if backend_agent is None:
            Settings.validate()
        
        self.session_id = session_id or f"session_{uuid4().hex[:10]}"

        self.memory = memory if memory is not None else ConversationMemory()

        self.session_manager = SessionManager()

        self.backend_agent = backend_agent if backend_agent is not None else _AdaptiveSecurityAgent(verbose=verbose)
        
        _restore_memory_from_session(self.memory, self.session_manager, self.session_id)

    def invoke(
        self,
        payload: Any,
        *,
        memory_user_text: Optional[str] = None,
        routing_text: Optional[str] = None,
    ) -> Any:
        """Invoke the G1 agent."""
        agent_input = extract_user_text(payload)
        memory_key = memory_user_text if memory_user_text is not None else agent_input
        route_on = routing_text if routing_text is not None else memory_key

        user_message, context_chars = _build_g1_user_message_with_memory(
            agent_input=agent_input,
            recall_query=memory_key,
            memory=self.memory,
        )
        logger.debug(
            "Memory context block: %d chars; episodic=%d semantic=%d",
            context_chars,
            len(self.memory.episodic_memories),
            len(self.memory.semantic_facts),
        )

        result = _invoke_backend(
            self.backend_agent,
            user_message=user_message,
            routing_text=route_on,
        )

        answer_text = extract_response_text(result)
        self.memory.record_dialogue_turn(user_text=memory_key, assistant_text=answer_text)
        self.session_manager.save_session(self.session_id, self.memory.get_state())

        return result


def create_g1_agent(
    *,
    session_id: Optional[str] = None,
    verbose: bool = False,
) -> G1Agent:
    return G1Agent(session_id=session_id, verbose=verbose)
