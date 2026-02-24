"""Memory-enabled cybersecurity agent wrapper."""

from typing import Any, Optional
from uuid import uuid4

from src.agents.g1.simple_agent import AdaptiveSecurityAgent
from src.utils.memory_manager import ConversationMemory
from src.utils.session_manager import SessionManager
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class StatefulSecurityAgent:
    """Wrap the adaptive agent with memory and session persistence."""

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
        self.session_id = session_id or f"session_{uuid4().hex[:10]}"
        self.memory = ConversationMemory(
            memory_type=memory_type,
            max_messages=max_messages,
            max_episodic_items=max_episodic_items,
            max_semantic_facts=max_semantic_facts,
            recall_top_k=recall_top_k,
        )
        self.session_manager = SessionManager()
        self.backend_agent = backend_agent or AdaptiveSecurityAgent(verbose=verbose)

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
        """Invoke backend agent with memory-aware context injection."""
        user_text = self._extract_user_text(payload)
        context_block = self.memory.render_context(query=user_text)
        augmented_prompt = (
            "Use this conversation context when answering.\n\n"
            f"{context_block}\n\n"
            f"Current user request:\n{user_text}"
        )

        result = self.backend_agent.invoke({"messages": [("user", augmented_prompt)]})
        answer_text = self._extract_response_text(result)

        self.memory.add_turn("user", user_text)
        self.memory.add_turn("assistant", answer_text)
        self.memory.update_long_term_from_turn(user_text=user_text, assistant_text=answer_text)
        self._persist()
        return result

    def run(self, user_input: str) -> str:
        """Convenience method returning plain text output."""
        result = self.invoke({"input": user_input})
        return self._extract_response_text(result)

    def _persist(self):
        self.session_manager.save_session(self.session_id, self.memory.get_state())

    @staticmethod
    def _extract_user_text(payload: Any) -> str:
        if isinstance(payload, dict):
            if "input" in payload:
                return str(payload["input"])
            if "messages" in payload and payload["messages"]:
                last = payload["messages"][-1]
                if isinstance(last, tuple) and len(last) == 2:
                    return str(last[1])
                return str(last)
        return str(payload)

    @staticmethod
    def _extract_response_text(result: Any) -> str:
        if isinstance(result, dict):
            if "output" in result:
                return str(result["output"])
            if "messages" in result and result["messages"]:
                last = result["messages"][-1]
                if hasattr(last, "content"):
                    return str(last.content)
                if isinstance(last, tuple) and len(last) == 2:
                    return str(last[1])
                return str(last)
        if hasattr(result, "content"):
            return str(result.content)
        return str(result)


def create_agent_with_memory(
    memory_type: str = "buffer",
    max_messages: int = 12,
    max_episodic_items: int = 30,
    max_semantic_facts: int = 80,
    recall_top_k: int = 3,
    session_id: Optional[str] = None,
    verbose: bool = True,
) -> StatefulSecurityAgent:
    """Factory for memory-enabled agent."""
    return StatefulSecurityAgent(
        memory_type=memory_type,
        max_messages=max_messages,
        max_episodic_items=max_episodic_items,
        max_semantic_facts=max_semantic_facts,
        recall_top_k=recall_top_k,
        session_id=session_id,
        verbose=verbose,
    )
