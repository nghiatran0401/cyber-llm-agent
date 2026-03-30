"""
Purpose: G1 security agent — tools, adaptive model routing, and session memory
What it does:
- Builds LangChain agents with security analysis tools
- Routes each request to fast or strong model by risk intent
- Persists conversation state by session ID and injects memory into prompts
"""

from typing import Any, Optional
from uuid import uuid4
from src.config.settings import Settings
from src.utils.logger import setup_logger
from src.utils.prompt_templates import load_prompt_template

from langchain.agents import create_agent
from langchain_openai import ChatOpenAI

from src.agents.g1.llm_payload import extract_response_text, extract_user_text
from src.agents.shared.intent_routing import is_high_risk_intent
from src.tools.cti_tool import cti_fetch
from src.tools.log_parser_tool import log_parser
from src.tools.rag_tools import rag_retriever
from src.utils.memory_manager import ConversationMemory
from src.utils.session_manager import SessionManager

logger = setup_logger(__name__)


def _create_tool_agent(model_name: str, verbose: bool = True):
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
    """Picks fast vs strong tool-enabled LLM per request (intent-based routing)."""

    def __init__(self, verbose: bool = True):
        Settings.validate()
        self.verbose = verbose
        self.fast_model = Settings.FAST_MODEL_NAME
        self.strong_model = Settings.STRONG_MODEL_NAME

        self.fast_agent = _create_tool_agent(self.fast_model, verbose=verbose)
        self.strong_agent = _create_tool_agent(self.strong_model, verbose=verbose)

        logger.info(
            "Initialized G1 model routing (fast=%s, strong=%s, intent_routing=on)",
            self.fast_model,
            self.strong_model,
        )

    def invoke(self, payload: Any, *, routing_text: Optional[str] = None) -> Any:
        """Route to the appropriate model and invoke the underlying agent."""

        user_text = routing_text if routing_text is not None else extract_user_text(payload)
        is_high_risk = is_high_risk_intent(user_text)
        selected_agent = self.strong_agent if is_high_risk else self.fast_agent
        return selected_agent.invoke(payload)


class G1Agent:
    """G1 agent: session memory plus default intent-based model routing."""

    def __init__(
        self,
        memory_type: str = "buffer",
        max_messages: int = 12,
        max_episodic_items: int = 30,
        max_semantic_facts: int = 80,
        max_context_chars: int = 4000,
        recall_top_k: int = 3,
        session_id: Optional[str] = None,
        backend_agent: Optional[Any] = None,
        verbose: bool = True,
    ):
        Settings.validate()
        self.session_id = session_id or f"session_{uuid4().hex[:10]}"
        self.memory = ConversationMemory(
            memory_type=memory_type,
            max_messages=max_messages,
            max_episodic_items=max_episodic_items,
            max_semantic_facts=max_semantic_facts,
            max_context_chars=max_context_chars,
            recall_top_k=recall_top_k,
        )
        self.session_manager = SessionManager()
        self.backend_agent = backend_agent or _AdaptiveSecurityAgent(verbose=verbose)

        existing = self.session_manager.load_session(self.session_id)
        if existing:
            self.memory.load_state(
                messages=existing.get("messages", []),
                running_summary=existing.get("running_summary", ""),
                episodic_memories=existing.get("episodic_memories", []),
                semantic_facts=existing.get("semantic_facts", []),
            )
            logger.info("Loaded existing session: %s", self.session_id)
        else:
            logger.info("Created new session: %s", self.session_id)

    def invoke(
        self,
        payload: Any,
        *,
        memory_user_text: Optional[str] = None,
        routing_text: Optional[str] = None,
    ):
        """Invoke the backend with memory-aware context injection.

        ``memory_user_text`` / ``routing_text`` default to the payload's user string.
        When the API wraps the analyst message in a large service prompt, pass the
        cleaned user utterance for recall, routing, and stored turns so memory and
        model tier stay aligned with trace metadata.
        """
        agent_input = extract_user_text(payload)
        memory_key = memory_user_text if memory_user_text is not None else agent_input
        route_on = routing_text if routing_text is not None else memory_key

        context_block = self.memory.render_context(query=memory_key)
        logger.debug(
            "Memory context size: %d chars, %d episodic, %d semantic",
            len(context_block),
            len(self.memory.episodic_memories),
            len(self.memory.semantic_facts),
        )
        augmented_prompt = (
            "Use this conversation context when answering.\n\n"
            f"{context_block}\n\n"
            f"Current user request:\n{agent_input}"
        )

        invoke_payload = {"messages": [("user", augmented_prompt)]}
        backend = self.backend_agent
        if isinstance(backend, _AdaptiveSecurityAgent):
            result = backend.invoke(invoke_payload, routing_text=route_on)
        else:
            result = backend.invoke(invoke_payload)

        answer_text = extract_response_text(result)

        self.memory.add_turn("user", memory_key)
        self.memory.add_turn("assistant", answer_text)
        self.memory.update_long_term_from_turn(user_text=memory_key, assistant_text=answer_text)
        self._persist()
        return result

    def run(
        self,
        user_input: str,
        *,
        memory_user_text: Optional[str] = None,
        routing_text: Optional[str] = None,
    ) -> str:
        """Convenience method returning plain text output."""
        result = self.invoke(
            {"input": user_input},
            memory_user_text=memory_user_text,
            routing_text=routing_text,
        )
        return extract_response_text(result)

    def _persist(self):
        self.session_manager.save_session(self.session_id, self.memory.get_state())


def create_g1_agent(
    memory_type: str = "buffer",
    max_messages: int = 12,
    max_episodic_items: int = 30,
    max_semantic_facts: int = 80,
    max_context_chars: int = 4000,
    recall_top_k: int = 3,
    session_id: Optional[str] = None,
    verbose: bool = True,
) -> G1Agent:
    """Construct a G1 agent with default routing and session memory."""
    return G1Agent(
        memory_type=memory_type,
        max_messages=max_messages,
        max_episodic_items=max_episodic_items,
        max_semantic_facts=max_semantic_facts,
        max_context_chars=max_context_chars,
        recall_top_k=recall_top_k,
        session_id=session_id,
        verbose=verbose,
    )
