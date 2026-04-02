"""Conversation memory manager for short-term and long-term memory."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.utils.embedding import EmbeddingMemory
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


@dataclass
class ConversationMemory:
    """Maintain chat history with buffer or summary strategy.

    Short-term memory: recent messages kept in ``messages`` up to
    ``max_messages``. Overflow is either dropped (buffer) or compressed
    into ``running_summary`` (summary).

    Long-term memory: episodic episodes and semantic facts stored
    indefinitely up to their respective caps. Recall uses cosine similarity
    when an embedding_memory is available, otherwise falls back to BM25.
    """

    memory_type: str = "buffer"
    max_messages: int = 12
    max_summary_chars: int = 1200
    max_episodic_items: int = 30
    max_semantic_facts: int = 80
    max_context_chars: int = 10_000
    recall_top_k: int = 3
    messages: List[Dict[str, str]] = field(default_factory=list)
    running_summary: str = ""
    episodic_memories: List[Dict[str, Any]] = field(default_factory=list)
    semantic_facts: List[str] = field(default_factory=list)

    # Parallel embedding vectors — excluded from get_state(), re-built on load_state().
    _episodic_embeddings: List[Optional[List[float]]] = field(default_factory=list, repr=False)
    _semantic_embeddings: List[Optional[List[float]]] = field(default_factory=list, repr=False)
    _embedding_backend: Optional[EmbeddingMemory] = field(default=None, repr=False)

    def __post_init__(self):
        allowed = {"buffer", "summary"}
        if self.memory_type not in allowed:
            raise ValueError(
                f"Unsupported memory_type '{self.memory_type}'. Use one of {allowed}."
            )
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

    def _ensure_embedding_backend(self) -> Optional[EmbeddingMemory]:
        """Lazily construct the embedding backend on first use (avoids I/O at dataclass init)."""
        if self._embedding_backend is not None:
            return self._embedding_backend
        try:
            self._embedding_backend = EmbeddingMemory.from_settings()
        except Exception as exc:
            logger.warning("Could not initialise embedding backend: %s", exc)
            self._embedding_backend = EmbeddingMemory(enabled=False)
        return self._embedding_backend

    # Public API — short-term memory

    def add_turn(self, role: str, content: str) -> None:
        """Append a user/assistant message and enforce buffer/summary limits."""
        if not content:
            return
        allowed_roles = {"user", "assistant", "system"}
        if role not in allowed_roles:
            raise ValueError(
                f"Invalid role '{role}'. Must be one of {sorted(allowed_roles)}."
            )
        self.messages.append({"role": role, "content": content})
        self._enforce_limits()

    def load_state(
        self,
        messages: List[Dict[str, str]],
        running_summary: str = "",
        episodic_memories: List[Dict[str, Any]] | None = None,
        semantic_facts: List[str] | None = None,
    ) -> None:
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

        self.messages = validated_messages
        self.running_summary = str(running_summary or "")[:self.max_summary_chars]
        self.episodic_memories = [
            ep for ep in (episodic_memories or [])
            if isinstance(ep, dict) and "summary" in ep
        ]
        self.semantic_facts = [
            str(item).strip() for item in (semantic_facts or []) if str(item).strip()
        ]
        self._enforce_limits()
        self._enforce_long_term_limits()

        # Re-embed all loaded entries — embeddings are never persisted to disk.
        self._episodic_embeddings = [
            self._embed(ep.get("summary", "")) for ep in self.episodic_memories
        ]
        self._semantic_embeddings = [
            self._embed(fact) for fact in self.semantic_facts
        ]

    def get_state(self) -> Dict[str, object]:
        """Return serializable memory state. Embeddings excluded by design."""
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
        """Render conversation context for prompt injection, capped at max_context_chars.

        When over budget, **drop oldest chat turns first** so the latest user/assistant
        exchange stays intact. The previous implementation took the head+tail of the whole
        blob, which often removed the middle of a long triage answer and broke follow-ups
        (\"what's VPN?\" with no VPN in context).
        """
        if (
            not self.messages
            and not self.running_summary
            and not self.episodic_memories
            and not self.semantic_facts
        ):
            return "No prior conversation context."

        recalled = self.retrieve_relevant_memories(query)
        recall_chunk = ""
        if recalled:
            recall_chunk = "Relevant long-term memory:\n" + "\n".join(
                f"- {item}" for item in recalled
            )

        summary_chunk = ""
        if self.running_summary:
            summary_chunk = f"Conversation summary so far:\n{self.running_summary}"

        sep = "\n\n"
        recent_header = "Recent conversation:\n"

        def _build_full_context(recent_body: str) -> str:
            blocks: List[str] = []
            if summary_chunk:
                blocks.append(summary_chunk)
            if recent_body:
                blocks.append(recent_header + recent_body)
            if recall_chunk:
                blocks.append(recall_chunk)
            return sep.join(blocks)

        recent_body = ""
        if self.messages:
            msgs = list(self.messages)
            while msgs:
                body = "\n".join(f"{m['role'].upper()}: {m['content']}" for m in msgs)
                if len(_build_full_context(body)) <= self.max_context_chars:
                    recent_body = body
                    break
                if len(msgs) >= 2:
                    if len(msgs) == 2:
                        # Dropping both would leave no recent context; keep latest turn.
                        msgs = [msgs[-1]]
                    else:
                        msgs = msgs[2:]
                    continue
                role = msgs[0]["role"].upper()
                raw = msgs[0]["content"]
                head = f"{role}: "
                lo, hi = 0, len(raw)
                best = head + raw[: min(len(raw), 400)] + "\n...[truncated]..."
                while lo <= hi:
                    mid = (lo + hi) // 2
                    suffix = "\n...[truncated]..." if mid < len(raw) else ""
                    piece = head + raw[:mid] + suffix
                    if len(_build_full_context(piece)) <= self.max_context_chars:
                        best = piece
                        lo = mid + 1
                    else:
                        hi = mid - 1
                recent_body = best
                break

        full_context = _build_full_context(recent_body)
        if len(full_context) > self.max_context_chars:
            full_context = (
                full_context[: self.max_context_chars - 40].rstrip() + "\n...[context hard-capped]..."
            )
        return full_context

    # Public API — long-term memory

    def add_episodic_memory(self, summary: str, tags: List[str] | None = None) -> None:
        """Store a short episode summary with optional tags."""
        cleaned = (summary or "").strip()
        if not cleaned:
            return
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": cleaned[:300],
            "tags": ", ".join(
                sorted({tag.strip().lower() for tag in (tags or []) if tag.strip()})
            ),
        }
        self.episodic_memories.append(entry)
        self._episodic_embeddings.append(self._embed(cleaned))
        self._enforce_long_term_limits()

    def add_semantic_fact(self, fact: str) -> None:
        """Store a stable fact. Silently skips exact duplicates."""
        cleaned = (fact or "").strip()
        if not cleaned or cleaned in self.semantic_facts:
            return
        self.semantic_facts.append(cleaned[:240])
        self._semantic_embeddings.append(self._embed(cleaned))
        self._enforce_long_term_limits()

    def update_long_term_from_turn(self, user_text: str, assistant_text: str) -> None:
        """Derive episodic and semantic memory from one interaction turn."""
        user_clean = (user_text or "").strip()
        assistant_clean = (assistant_text or "").strip()
        if not user_clean and not assistant_clean:
            return
        episode = f"user={user_clean[:120]} | assistant={assistant_clean[:140]}"
        self.add_episodic_memory(episode, tags=self._infer_tags(user_clean + "\n" + assistant_clean))
        for fact in self._extract_semantic_facts(assistant_clean):
            self.add_semantic_fact(fact)

    def retrieve_relevant_memories(
        self, query: str, max_items: int | None = None
    ) -> List[str]:
        """Rank memories by cosine similarity when available, else BM25."""
        limit = max_items or self.recall_top_k
        query_embedding = self._embed(query)
        if query_embedding is not None:
            return self._retrieve_by_embedding(query_embedding, limit)
        return self._retrieve_by_bm25(query, limit)

    # Private — recall

    def _embed(self, text: str) -> Optional[List[float]]:
        return self._ensure_embedding_backend().embed(text)

    def _retrieve_by_embedding(self, query_vec: List[float], limit: int) -> List[str]:
        scored: List[tuple[float, str]] = []
        cosine = EmbeddingMemory.cosine_similarity

        for i, memory in enumerate(self.episodic_memories):
            summary = str(memory.get("summary", "")).strip()
            if not summary:
                continue
            vec = self._episodic_embeddings[i] if i < len(self._episodic_embeddings) else None
            if vec is None:
                vec = self._embed(summary)
                if i < len(self._episodic_embeddings):
                    self._episodic_embeddings[i] = vec  # backfill
            if vec is None:
                continue
            recency = (i + 1) / max(len(self.episodic_memories), 1)
            scored.append((cosine(query_vec, vec) * (1 + 0.2 * recency), f"Episodic: {summary}"))

        for i, fact in enumerate(self.semantic_facts):
            vec = self._semantic_embeddings[i] if i < len(self._semantic_embeddings) else None
            if vec is None:
                vec = self._embed(fact)
                if i < len(self._semantic_embeddings):
                    self._semantic_embeddings[i] = vec  # backfill
            if vec is None:
                continue
            scored.append((cosine(query_vec, vec), f"Semantic: {fact}"))

        scored.sort(key=lambda x: x[0], reverse=True)
        return self._deduplicate(scored, limit)

    def _retrieve_by_bm25(self, query: str, limit: int) -> List[str]:
        """BM25 fallback — used when embedding backend is disabled or unavailable."""
        query_tokens = self._tokens_list(query)
        if not query_tokens:
            return []

        doc_entries: List[tuple[list[str], str, int]] = []
        for i, memory in enumerate(self.episodic_memories):
            summary = str(memory.get("summary", "")).strip()
            if not summary:
                continue
            doc_entries.append((self._tokens_list(summary), f"Episodic: {summary}", i))
        for fact in self.semantic_facts:
            doc_entries.append((self._tokens_list(fact), f"Semantic: {fact}", -1))

        if not doc_entries:
            return []

        corpus_tokens = [dt for dt, _, _ in doc_entries]
        corpus_size = len(corpus_tokens)
        avg_doc_len = sum(len(dt) for dt in corpus_tokens) / max(corpus_size, 1)

        idf_map: dict[str, float] = {}
        for term in set(query_tokens):
            df = sum(1 for dt in corpus_tokens if term in set(dt))
            idf_map[term] = self._bm25_idf(df, corpus_size)

        scored: List[tuple[float, str]] = []
        for doc_tokens, label, episodic_idx in doc_entries:
            score = self._bm25_doc_score(
                query_tokens, doc_tokens, idf_map, avg_doc_len=avg_doc_len
            )
            if score <= 0:
                continue
            if episodic_idx >= 0:
                recency = (episodic_idx + 1) / max(len(self.episodic_memories), 1)
                score *= 1 + 0.2 * recency
            scored.append((score, label))

        scored.sort(key=lambda x: x[0], reverse=True)
        return self._deduplicate(scored, limit)

    @staticmethod
    def _deduplicate(scored: List[tuple[float, str]], limit: int) -> List[str]:
        seen: set[str] = set()
        results: List[str] = []
        for _, text in scored:
            key = text[:60].lower()
            if key not in seen:
                seen.add(key)
                results.append(text)
            if len(results) >= limit:
                break
        return results

    # Private — buffer / summary limits

    def _enforce_limits(self) -> None:
        if len(self.messages) <= self.max_messages:
            return
        overflow_count = len(self.messages) - self.max_messages
        overflow = self.messages[:overflow_count]
        self.messages = self.messages[overflow_count:]
        if self.memory_type == "summary":
            self._update_summary(overflow)

    def _update_summary(self, overflow_messages: List[Dict[str, str]]) -> None:
        lines = []
        for msg in overflow_messages:
            first_sentence = msg["content"].split(".")[0][:120]
            ellipsis = "..." if len(msg["content"]) > 120 else ""
            lines.append(f"{msg['role']}: {first_sentence}{ellipsis}")
        compressed = "\n".join(lines)
        self.running_summary = (
            f"{self.running_summary}\n---\n{compressed}"
            if self.running_summary
            else compressed
        )
        if len(self.running_summary) > self.max_summary_chars:
            self.running_summary = (
                "...[earlier context trimmed]...\n"
                + self.running_summary[-self.max_summary_chars:]
            )

    def _enforce_long_term_limits(self) -> None:
        if len(self.episodic_memories) > self.max_episodic_items:
            trim = len(self.episodic_memories) - self.max_episodic_items
            self.episodic_memories = self.episodic_memories[trim:]
            self._episodic_embeddings = self._episodic_embeddings[trim:]
        if len(self.semantic_facts) > self.max_semantic_facts:
            trim = len(self.semantic_facts) - self.max_semantic_facts
            self.semantic_facts = self.semantic_facts[trim:]
            self._semantic_embeddings = self._semantic_embeddings[trim:]

    # Private — BM25 scoring

    @staticmethod
    def _tokens_list(text: str) -> list[str]:
        return [t.lower() for t in re.findall(r"[a-zA-Z0-9_.:-]{2,}", text or "")]

    @staticmethod
    def _bm25_idf(df: int, corpus_size: int) -> float:
        """Okapi BM25 inverse document frequency using corpus-wide document frequency."""
        if corpus_size <= 0:
            return 0.0
        return math.log((corpus_size - df + 0.5) / (df + 0.5) + 1.0)

    @staticmethod
    def _bm25_doc_score(
        query_tokens: list[str],
        doc_tokens: list[str],
        idf_map: dict[str, float],
        avg_doc_len: float = 20.0,
        k1: float = 1.5,
        b: float = 0.75,
    ) -> float:
        if not query_tokens or not doc_tokens:
            return 0.0
        doc_len = len(doc_tokens)
        doc_freq = Counter(doc_tokens)
        score = 0.0
        for term in query_tokens:
            tf = doc_freq.get(term, 0)
            if tf == 0:
                continue
            idf = idf_map.get(term, 0.0)
            tf_norm = (tf * (k1 + 1)) / (tf + k1 * (1 - b + b * (doc_len / avg_doc_len)))
            score += idf * tf_norm
        return score

    # Private — tagging and fact extraction

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