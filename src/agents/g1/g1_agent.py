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

from src.agents.shared.intent_routing import is_high_risk_intent
from src.tools.cti_tool import cti_fetch
from src.tools.log_parser_tool import log_parser
from src.tools.rag_tools import rag_retriever
from src.utils.memory_manager import ConversationMemory
from src.utils.session_manager import SessionManager

logger = setup_logger(__name__)

# helper function to extract the user text from the invoke payload
def _extract_user_text_from_invoke_payload(payload: Any) -> str:
    """Normalize LangChain-style invoke payloads to a single user string."""
    if isinstance(payload, dict):
        raw = payload.get("input")
        if isinstance(raw, str):
            return raw
        messages = payload.get("messages")
        if messages:
            last = messages[-1]
            if isinstance(last, tuple) and len(last) == 2:
                return str(last[1])
            return str(last)
    return str(payload)

# helper function to extract the response text from the result
def _extract_response_text(result: Any) -> str:
    if isinstance(result, dict):
        if "output" in result:
            return str(result["output"])
        messages = result.get("messages")
        if messages:
            last = messages[-1]
            if hasattr(last, "content"):
                return str(last.content)
            if isinstance(last, tuple) and len(last) == 2:
                return str(last[1])
            return str(last)
    if hasattr(result, "content"):
        return str(result.content)
    return str(result)


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

        user_text = routing_text if routing_text is not None else _extract_user_text_from_invoke_payload(payload)
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

    def invoke(self, payload: Any):
        """Invoke the backend with memory-aware context injection."""
        user_text = _extract_user_text_from_invoke_payload(payload)
        context_block = self.memory.render_context(query=user_text)
        augmented_prompt = (
            "Use this conversation context when answering.\n\n"
            f"{context_block}\n\n"
            f"Current user request:\n{user_text}"
        )

        invoke_payload = {"messages": [("user", augmented_prompt)]}
        backend = self.backend_agent
        if isinstance(backend, _AdaptiveSecurityAgent):
            result = backend.invoke(invoke_payload, routing_text=user_text)
        else:
            result = backend.invoke(invoke_payload)

        answer_text = _extract_response_text(result)

        self.memory.add_turn("user", user_text)
        self.memory.add_turn("assistant", answer_text)
        self.memory.update_long_term_from_turn(user_text=user_text, assistant_text=answer_text)
        self._persist()
        return result

    def run(self, user_input: str) -> str:
        """Convenience method returning plain text output."""
        result = self.invoke({"input": user_input})
        return _extract_response_text(result)

    def _persist(self):
        self.session_manager.save_session(self.session_id, self.memory.get_state())


def create_g1_agent(
    memory_type: str = "buffer",
    max_messages: int = 12,
    max_episodic_items: int = 30,
    max_semantic_facts: int = 80,
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
        recall_top_k=recall_top_k,
        session_id=session_id,
        verbose=verbose,
    )
