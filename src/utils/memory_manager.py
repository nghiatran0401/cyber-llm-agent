"""Conversation memory helpers for stateful agent interactions."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Dict, List


@dataclass
class ConversationMemory:
    """Maintain chat history with buffer or summary strategy."""

    memory_type: str = "buffer"
    max_messages: int = 12
    max_summary_chars: int = 1200
    max_episodic_items: int = 30
    max_semantic_facts: int = 80
    recall_top_k: int = 3
    messages: List[Dict[str, str]] = field(default_factory=list)
    running_summary: str = ""
    episodic_memories: List[Dict[str, str]] = field(default_factory=list)
    semantic_facts: List[str] = field(default_factory=list)

    def __post_init__(self):
        allowed = {"buffer", "summary"}
        if self.memory_type not in allowed:
            raise ValueError(f"Unsupported memory_type '{self.memory_type}'. Use one of {allowed}.")
        if self.max_messages < 2:
            raise ValueError("max_messages must be at least 2.")
        if self.max_episodic_items <= 0:
            raise ValueError("max_episodic_items must be greater than 0.")
        if self.max_semantic_facts <= 0:
            raise ValueError("max_semantic_facts must be greater than 0.")
        if self.recall_top_k <= 0:
            raise ValueError("recall_top_k must be greater than 0.")

    def add_turn(self, role: str, content: str):
        """Append a user/assistant message and enforce limits."""
        if not content:
            return
        self.messages.append({"role": role, "content": content})
        self._enforce_limits()

    def load_state(
        self,
        messages: List[Dict[str, str]],
        running_summary: str = "",
        episodic_memories: List[Dict[str, str]] | None = None,
        semantic_facts: List[str] | None = None,
    ):
        """Restore memory state from persisted data."""
        self.messages = list(messages or [])
        self.running_summary = running_summary or ""
        self.episodic_memories = list(episodic_memories or [])
        self.semantic_facts = [str(item).strip() for item in (semantic_facts or []) if str(item).strip()]
        self._enforce_limits()
        self._enforce_long_term_limits()

    def get_state(self) -> Dict[str, object]:
        """Return serializable memory state."""
        return {
            "memory_type": self.memory_type,
            "max_messages": self.max_messages,
            "max_summary_chars": self.max_summary_chars,
            "max_episodic_items": self.max_episodic_items,
            "max_semantic_facts": self.max_semantic_facts,
            "recall_top_k": self.recall_top_k,
            "running_summary": self.running_summary,
            "messages": self.messages,
            "episodic_memories": self.episodic_memories,
            "semantic_facts": self.semantic_facts,
        }

    def render_context(self, query: str = "") -> str:
        """Render conversation context that can be prepended to prompts."""
        if not self.messages and not self.running_summary and not self.episodic_memories and not self.semantic_facts:
            return "No prior conversation context."

        chunks: List[str] = []
        if self.running_summary:
            chunks.append(f"Conversation summary so far:\n{self.running_summary}")

        if self.messages:
            rendered = "\n".join(f"{msg['role'].upper()}: {msg['content']}" for msg in self.messages)
            chunks.append(f"Recent conversation:\n{rendered}")

        recalled = self.retrieve_relevant_memories(query)
        if recalled:
            chunks.append("Relevant long-term memory:\n" + "\n".join(f"- {item}" for item in recalled))

        return "\n\n".join(chunks)

    def add_episodic_memory(self, summary: str, tags: List[str] | None = None):
        """Store a short episode summary for long-term recall."""
        cleaned = (summary or "").strip()
        if not cleaned:
            return
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": cleaned[:300],
            "tags": ", ".join(sorted({tag.strip().lower() for tag in (tags or []) if tag.strip()})),
        }
        self.episodic_memories.append(entry)
        self._enforce_long_term_limits()

    def add_semantic_fact(self, fact: str):
        """Store stable fact-like memory for future grounding."""
        cleaned = (fact or "").strip()
        if not cleaned:
            return
        if cleaned in self.semantic_facts:
            return
        self.semantic_facts.append(cleaned[:240])
        self._enforce_long_term_limits()

    def update_long_term_from_turn(self, user_text: str, assistant_text: str):
        """Derive episodic and semantic memory from one interaction turn."""
        user_clean = (user_text or "").strip()
        assistant_clean = (assistant_text or "").strip()
        if not user_clean and not assistant_clean:
            return
        episode = f"user={user_clean[:120]} | assistant={assistant_clean[:140]}"
        tags = self._infer_tags(user_clean + "\n" + assistant_clean)
        self.add_episodic_memory(episode, tags=tags)
        for fact in self._extract_semantic_facts(assistant_clean):
            self.add_semantic_fact(fact)

    def retrieve_relevant_memories(self, query: str, max_items: int | None = None) -> List[str]:
        """Return top relevant episodic/semantic entries for the current query."""
        query_tokens = self._tokens(query)
        limit = max_items or self.recall_top_k
        scored: List[tuple[float, str]] = []

        for memory in self.episodic_memories:
            summary = str(memory.get("summary", "")).strip()
            if not summary:
                continue
            score = self._token_overlap_score(query_tokens, self._tokens(summary))
            if score > 0:
                scored.append((score, f"Episodic: {summary}"))

        for fact in self.semantic_facts:
            score = self._token_overlap_score(query_tokens, self._tokens(fact))
            if score > 0:
                scored.append((score, f"Semantic: {fact}"))

        scored.sort(key=lambda item: item[0], reverse=True)
        return [item for _, item in scored[:limit]]

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

    def _enforce_long_term_limits(self):
        if len(self.episodic_memories) > self.max_episodic_items:
            self.episodic_memories = self.episodic_memories[-self.max_episodic_items :]
        if len(self.semantic_facts) > self.max_semantic_facts:
            self.semantic_facts = self.semantic_facts[-self.max_semantic_facts :]

    @staticmethod
    def _tokens(text: str) -> set[str]:
        return {token.lower() for token in re.findall(r"[a-zA-Z0-9_.:-]{2,}", text or "")}

    @staticmethod
    def _token_overlap_score(query_tokens: set[str], text_tokens: set[str]) -> float:
        if not query_tokens or not text_tokens:
            return 0.0
        overlap = len(query_tokens.intersection(text_tokens))
        return overlap / max(len(query_tokens), 1)

    @staticmethod
    def _infer_tags(text: str) -> List[str]:
        lowered = (text or "").lower()
        tags: List[str] = []
        if "ransom" in lowered or "malware" in lowered:
            tags.append("malware")
        if "phish" in lowered:
            tags.append("phishing")
        if "failed login" in lowered or "brute" in lowered:
            tags.append("auth")
        if "sql" in lowered or "xss" in lowered:
            tags.append("appsec")
        if "ioc" in lowered or "cti" in lowered:
            tags.append("intel")
        if not tags:
            tags.append("general")
        return tags

    @staticmethod
    def _extract_semantic_facts(text: str) -> List[str]:
        facts: List[str] = []
        for raw_line in (text or "").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            lowered = line.lower()
            if lowered.startswith("source:"):
                facts.append(line)
                continue
            if any(marker in lowered for marker in ("severity", "confidence", "ioc", "#chunk-")):
                facts.append(line[:240])
        return facts[:6]

