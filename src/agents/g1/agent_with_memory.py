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
        session_id: Optional[str] = None,
        backend_agent: Optional[Any] = None,
        verbose: bool = True,
    ):
        self.session_id = session_id or f"session_{uuid4().hex[:10]}"
        self.memory = ConversationMemory(memory_type=memory_type, max_messages=max_messages)
        self.session_manager = SessionManager()
        self.backend_agent = backend_agent or AdaptiveSecurityAgent(verbose=verbose)

        existing = self.session_manager.load_session(self.session_id)
        if existing:
            self.memory.load_state(
                messages=existing.get("messages", []),
                running_summary=existing.get("running_summary", ""),
            )
            logger.info("Loaded existing session: %s", self.session_id)
        else:
            logger.info("Created new session: %s", self.session_id)

    def invoke(self, payload: Any):
        """Invoke backend agent with memory-aware context injection."""
        user_text = self._extract_user_text(payload)
        context_block = self.memory.render_context()
        augmented_prompt = (
            "Use this conversation context when answering.\n\n"
            f"{context_block}\n\n"
            f"Current user request:\n{user_text}"
        )

        result = self.backend_agent.invoke({"messages": [("user", augmented_prompt)]})
        answer_text = self._extract_response_text(result)

        self.memory.add_turn("user", user_text)
        self.memory.add_turn("assistant", answer_text)
        self._persist()
        return result

    def run(self, user_input: str) -> str:
        """Convenience method returning plain text output."""
        result = self.invoke({"input": user_input})
        return self._extract_response_text(result)

    def _persist(self):
        self.session_manager.save_session(
            self.session_id,
            {
                "running_summary": self.memory.running_summary,
                "messages": self.memory.messages,
            },
        )

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
    session_id: Optional[str] = None,
    verbose: bool = True,
) -> StatefulSecurityAgent:
    """Factory for memory-enabled agent."""
    return StatefulSecurityAgent(
        memory_type=memory_type,
        max_messages=max_messages,
        session_id=session_id,
        verbose=verbose,
    )
