"""Conversation memory helpers for stateful agent interactions."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Dict, List
import math
from collections import Counter


@dataclass
class ConversationMemory:
    """Maintain chat history with buffer or summary strategy."""

    memory_type: str = "buffer"
    max_messages: int = 12
    max_summary_chars: int = 1200
    max_episodic_items: int = 30
    max_semantic_facts: int = 80
    max_context_chars: int = 4000
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
        if self.max_context_chars < 500:
            raise ValueError("max_context_chars must be at least 500.")
        if self.recall_top_k <= 0:
            raise ValueError("recall_top_k must be greater than 0.")

    def add_turn(self, role: str, content: str):
        """Append a user/assistant message and enforce limits."""
        if not content:
            return
        self.messages.append({"role": role, "content": content})
        self._enforce_limits()

    # In ConversationMemory.load_state — replace the method body

    def load_state(
        self,
        messages: List[Dict[str, str]],
        running_summary: str = "",
        episodic_memories: List[Dict[str, str]] | None = None,
        semantic_facts: List[str] | None = None,
    ):
        """Restore memory state from persisted data with contract validation."""
        validated_messages = []
        for i, msg in enumerate(messages or []):
            if not isinstance(msg, dict):
                raise ValueError(f"messages[{i}] must be a dict, got {type(msg).__name__}")
            if "role" not in msg or "content" not in msg:
                raise ValueError(f"messages[{i}] missing required keys 'role' and/or 'content'")
            if msg["role"] not in {"user", "assistant", "system"}:
                raise ValueError(f"messages[{i}] has invalid role '{msg['role']}'")
            validated_messages.append({"role": str(msg["role"]), "content": str(msg["content"])})

        validated_episodic = []
        for i, ep in enumerate(episodic_memories or []):
            if not isinstance(ep, dict):
                continue  # skip malformed episodes rather than crashing
            if "summary" not in ep:
                continue
            validated_episodic.append(ep)

        self.messages = validated_messages
        self.running_summary = str(running_summary or "")[:self.max_summary_chars]
        self.episodic_memories = validated_episodic
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
        """Render conversation context for prompt injection, capped at max_context_chars."""
        if not self.messages and not self.running_summary and not self.episodic_memories and not self.semantic_facts:
            return "No prior conversation context."

        chunks: List[str] = []
        if self.running_summary:
            chunks.append(f"Conversation summary so far:\n{self.running_summary}")

        if self.messages:
            rendered = "\n".join(
                f"{msg['role'].upper()}: {msg['content']}" for msg in self.messages
            )
            chunks.append(f"Recent conversation:\n{rendered}")

        recalled = self.retrieve_relevant_memories(query)
        if recalled:
            chunks.append("Relevant long-term memory:\n" + "\n".join(f"- {item}" for item in recalled))

        full_context = "\n\n".join(chunks)

        # Hard cap — truncate from the middle to preserve summary + most recent turn.
        if len(full_context) > self.max_context_chars:
            half = self.max_context_chars // 2
            full_context = (
                full_context[:half]
                + "\n...[context trimmed for length]...\n"
                + full_context[-half:]
            )
        return full_context

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
        """Return top relevant episodic/semantic entries scored with BM25 + recency."""
        query_token_list = self._tokens_list(query)
        if not query_token_list:
            return []
        limit = max_items or self.recall_top_k
        scored: list[tuple[float, str]] = []

        for i, memory in enumerate(self.episodic_memories):
            summary = str(memory.get("summary", "")).strip()
            if not summary:
                continue
            bm25 = self._bm25_score(query_token_list, self._tokens_list(summary))
            if bm25 <= 0:
                continue
            # Recency boost: later items in the list are more recent.
            recency = (i + 1) / max(len(self.episodic_memories), 1)
            final_score = bm25 * (1 + 0.2 * recency)
            scored.append((final_score, f"Episodic: {summary}"))

        for fact in self.semantic_facts:
            bm25 = self._bm25_score(query_token_list, self._tokens_list(fact))
            if bm25 > 0:
                scored.append((bm25, f"Semantic: {fact}"))

        scored.sort(key=lambda item: item[0], reverse=True)

        # Deduplicate by leading 60 chars to avoid near-duplicate recall items.
        seen: set[str] = set()
        results: list[str] = []
        for _, text in scored:
            key = text[:60].lower()
            if key not in seen:
                seen.add(key)
                results.append(text)
            if len(results) >= limit:
                break
        return results

    def _enforce_limits(self):
        """Trim memory using selected strategy."""
        if len(self.messages) <= self.max_messages:
            return

        overflow_count = len(self.messages) - self.max_messages
        overflow = self.messages[:overflow_count]
        self.messages = self.messages[overflow_count:]

        if self.memory_type == "summary":
            self._update_summary(overflow)

    def _update_summary(self, overflow_messages: List[Dict[str, str]]) -> None:
        """Create a human-readable rolling summary from trimmed turns."""
        lines = []
        for msg in overflow_messages:
            role = msg["role"]
            body = msg["content"]
            # Keep only first sentence of long turns to avoid summary bloat.
            first_sentence = body.split(".")[0][:120]
            ellipsis = "..." if len(body) > 120 else ""
            lines.append(f"{role}: {first_sentence}{ellipsis}")
        compressed = "\n".join(lines)

        if self.running_summary:
            self.running_summary = f"{self.running_summary}\n---\n{compressed}"
        else:
            self.running_summary = compressed

        if len(self.running_summary) > self.max_summary_chars:
            # Keep the tail (most recent compressed turns) not the head.
            self.running_summary = "...[earlier context trimmed]...\n" + \
                self.running_summary[-self.max_summary_chars:]

    def _enforce_long_term_limits(self):
        if len(self.episodic_memories) > self.max_episodic_items:
            self.episodic_memories = self.episodic_memories[-self.max_episodic_items :]
        if len(self.semantic_facts) > self.max_semantic_facts:
            self.semantic_facts = self.semantic_facts[-self.max_semantic_facts :]
    
    @staticmethod
    def _bm25_score(
        query_tokens: list[str],
        doc_tokens: list[str],
        avg_doc_len: float = 20.0,
        k1: float = 1.5,
        b: float = 0.75,
    ) -> float:
        """BM25 score"""
        if not query_tokens or not doc_tokens:
            return 0.0
        doc_len = len(doc_tokens)
        doc_freq = Counter(doc_tokens)
        score = 0.0
        for term in query_tokens:
            tf = doc_freq.get(term, 0)
            if tf == 0:
                continue
            idf = math.log(1 + (1 / (tf + 0.5)))  # simplified IDF without corpus stats
            tf_norm = (tf * (k1 + 1)) / (tf + k1 * (1 - b + b * (doc_len / avg_doc_len)))
            score += idf * tf_norm
        return score

    @staticmethod
    def _tokens_list(text: str) -> list[str]:
        """Return ordered token list (preserves duplicates for BM25 TF)."""
        return [t.lower() for t in re.findall(r"[a-zA-Z0-9_.:-]{2,}", text or "")]

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

