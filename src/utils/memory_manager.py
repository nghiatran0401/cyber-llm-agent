"""Conversation memory helpers for stateful agent interactions."""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class ConversationMemory:
    """Maintain chat history with buffer or summary strategy."""

    memory_type: str = "buffer"
    max_messages: int = 12
    max_summary_chars: int = 1200
    messages: List[Dict[str, str]] = field(default_factory=list)
    running_summary: str = ""

    def __post_init__(self):
        allowed = {"buffer", "summary"}
        if self.memory_type not in allowed:
            raise ValueError(f"Unsupported memory_type '{self.memory_type}'. Use one of {allowed}.")
        if self.max_messages < 2:
            raise ValueError("max_messages must be at least 2.")

    def add_turn(self, role: str, content: str):
        """Append a user/assistant message and enforce limits."""
        if not content:
            return
        self.messages.append({"role": role, "content": content})
        self._enforce_limits()

    def load_state(self, messages: List[Dict[str, str]], running_summary: str = ""):
        """Restore memory state from persisted data."""
        self.messages = list(messages or [])
        self.running_summary = running_summary or ""
        self._enforce_limits()

    def get_state(self) -> Dict[str, object]:
        """Return serializable memory state."""
        return {
            "memory_type": self.memory_type,
            "max_messages": self.max_messages,
            "max_summary_chars": self.max_summary_chars,
            "running_summary": self.running_summary,
            "messages": self.messages,
        }

    def render_context(self) -> str:
        """Render conversation context that can be prepended to prompts."""
        if not self.messages and not self.running_summary:
            return "No prior conversation context."

        chunks: List[str] = []
        if self.running_summary:
            chunks.append(f"Conversation summary so far:\n{self.running_summary}")

        if self.messages:
            rendered = "\n".join(f"{msg['role'].upper()}: {msg['content']}" for msg in self.messages)
            chunks.append(f"Recent conversation:\n{rendered}")

        return "\n\n".join(chunks)

    def _enforce_limits(self):
        """Trim memory using selected strategy."""
        if len(self.messages) <= self.max_messages:
            return

        overflow_count = len(self.messages) - self.max_messages
        overflow = self.messages[:overflow_count]
        self.messages = self.messages[overflow_count:]

        if self.memory_type == "summary":
            self._update_summary(overflow)

    def _update_summary(self, overflow_messages: List[Dict[str, str]]):
        """Create a lightweight rolling summary from trimmed turns."""
        compressed = " | ".join(
            f"{msg['role']}:{msg['content'][:80]}{'...' if len(msg['content']) > 80 else ''}"
            for msg in overflow_messages
        )
        if self.running_summary:
            self.running_summary = f"{self.running_summary} || {compressed}"
        else:
            self.running_summary = compressed

        if len(self.running_summary) > self.max_summary_chars:
            self.running_summary = "..." + self.running_summary[-self.max_summary_chars:]

