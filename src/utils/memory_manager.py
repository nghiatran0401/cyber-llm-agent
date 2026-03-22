"""Conversation memory helpers for stateful agent interactions."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from src.utils.logger import setup_logger

logger = setup_logger(__name__)


# ---------------------------------------------------------------------------
# Embedding backend
# ---------------------------------------------------------------------------

class EmbeddingBackend:
    """Thin wrapper that returns float vectors from either OpenAI or Ollama."""

    def __init__(
        self,
        provider: str = "openai",
        openai_model: str = "text-embedding-3-small",
        ollama_base_url: str = "http://localhost:11434",
        ollama_model: str = "nomic-embed-text",
        enabled: bool = True,
    ):
        allowed = {"openai", "ollama"}
        if provider not in allowed:
            raise ValueError(f"EmbeddingBackend provider must be one of {allowed}; got '{provider}'.")
        self.provider = provider
        self.openai_model = openai_model
        self.ollama_base_url = ollama_base_url.rstrip("/")
        self.ollama_model = ollama_model
        self.enabled = enabled
        self._openai_client = None  # lazy-init to avoid import cost at module load

    def embed(self, text: str) -> Optional[List[float]]:
        """Return an embedding vector, or None if unavailable/disabled."""
        if not self.enabled or not text.strip():
            return None
        try:
            if self.provider == "openai":
                return self._embed_openai(text)
            return self._embed_ollama(text)
        except Exception as exc:
            logger.warning("Embedding failed (%s), falling back to BM25: %s", self.provider, exc)
            return None

    def _embed_openai(self, text: str) -> List[float]:
        if self._openai_client is None:
            from openai import OpenAI
            self._openai_client = OpenAI()
        response = self._openai_client.embeddings.create(
            input=text[:8000],  # stay within token limit
            model=self.openai_model,
        )
        return response.data[0].embedding

    def _embed_ollama(self, text: str) -> List[float]:
        import urllib.request
        import json as _json
        payload = _json.dumps({"model": self.ollama_model, "prompt": text[:8000]}).encode()
        req = urllib.request.Request(
            f"{self.ollama_base_url}/api/embeddings",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = _json.loads(resp.read().decode())
        return result["embedding"]

    @staticmethod
    def cosine_similarity(a: List[float], b: List[float]) -> float:
        """Cosine similarity between two equal-length vectors."""
        if not a or not b or len(a) != len(b):
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0
        return dot / (norm_a * norm_b)

    @classmethod
    def from_settings(cls) -> "EmbeddingBackend":
        """Construct from Settings without circular imports."""
        from src.config.settings import Settings
        return cls(
            provider=Settings.EMBEDDING_PROVIDER,
            openai_model=Settings.OPENAI_EMBEDDING_MODEL,
            ollama_base_url=Settings.OLLAMA_BASE_URL,
            ollama_model=Settings.OLLAMA_EMBEDDING_MODEL,
            enabled=Settings.EMBEDDING_ENABLED,
        )


# ---------------------------------------------------------------------------
# Conversation memory
# ---------------------------------------------------------------------------

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
    episodic_memories: List[Dict] = field(default_factory=list)
    semantic_facts: List[str] = field(default_factory=list)

    # Embedding vectors stored parallel to episodic/semantic lists.
    # Not persisted to session JSON — re-embedded on load_state.
    _episodic_embeddings: List[Optional[List[float]]] = field(
        default_factory=list, repr=False
    )
    _semantic_embeddings: List[Optional[List[float]]] = field(
        default_factory=list, repr=False
    )
    _embedding_backend: Optional[EmbeddingBackend] = field(
        default=None, repr=False
    )

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
        if self._embedding_backend is None:
            try:
                self._embedding_backend = EmbeddingBackend.from_settings()
            except Exception as exc:
                logger.warning("Could not initialise embedding backend: %s", exc)
                self._embedding_backend = EmbeddingBackend(enabled=False)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_turn(self, role: str, content: str):
        if not content:
            return
        self.messages.append({"role": role, "content": content})
        self._enforce_limits()

    def load_state(
        self,
        messages: List[Dict[str, str]],
        running_summary: str = "",
        episodic_memories: List[Dict] | None = None,
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
        for ep in (episodic_memories or []):
            if isinstance(ep, dict) and "summary" in ep:
                validated_episodic.append(ep)

        self.messages = validated_messages
        self.running_summary = str(running_summary or "")[:self.max_summary_chars]
        self.episodic_memories = validated_episodic
        self.semantic_facts = [
            str(item).strip() for item in (semantic_facts or []) if str(item).strip()
        ]
        self._enforce_limits()
        self._enforce_long_term_limits()

        # Re-embed all loaded entries (embeddings are not persisted to disk).
        self._episodic_embeddings = [
            self._embed(ep.get("summary", "")) for ep in self.episodic_memories
        ]
        self._semantic_embeddings = [
            self._embed(fact) for fact in self.semantic_facts
        ]

    def get_state(self) -> Dict[str, object]:
        """Return serializable memory state — embeddings intentionally excluded."""
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
        if (
            not self.messages
            and not self.running_summary
            and not self.episodic_memories
            and not self.semantic_facts
        ):
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
            chunks.append(
                "Relevant long-term memory:\n" + "\n".join(f"- {item}" for item in recalled)
            )

        full_context = "\n\n".join(chunks)
        if len(full_context) > self.max_context_chars:
            half = self.max_context_chars // 2
            full_context = (
                full_context[:half]
                + "\n...[context trimmed for length]...\n"
                + full_context[-half:]
            )
        return full_context

    def add_episodic_memory(self, summary: str, tags: List[str] | None = None):
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

    def add_semantic_fact(self, fact: str):
        cleaned = (fact or "").strip()
        if not cleaned or cleaned in self.semantic_facts:
            return
        self.semantic_facts.append(cleaned[:240])
        self._semantic_embeddings.append(self._embed(cleaned))
        self._enforce_long_term_limits()

    def update_long_term_from_turn(self, user_text: str, assistant_text: str):
        user_clean = (user_text or "").strip()
        assistant_clean = (assistant_text or "").strip()
        if not user_clean and not assistant_clean:
            return
        episode = f"user={user_clean[:120]} | assistant={assistant_clean[:140]}"
        tags = self._infer_tags(user_clean + "\n" + assistant_clean)
        self.add_episodic_memory(episode, tags=tags)
        for fact in self._extract_semantic_facts(assistant_clean):
            self.add_semantic_fact(fact)

    def retrieve_relevant_memories(
        self, query: str, max_items: int | None = None
    ) -> List[str]:
        """Rank memories by cosine similarity if embeddings available, else BM25."""
        limit = max_items or self.recall_top_k
        query_embedding = self._embed(query)

        if query_embedding is not None:
            return self._retrieve_by_embedding(query_embedding, limit)
        return self._retrieve_by_bm25(query, limit)

    # ------------------------------------------------------------------
    # Internal — embedding helpers
    # ------------------------------------------------------------------

    def _embed(self, text: str) -> Optional[List[float]]:
        if self._embedding_backend is None:
            return None
        return self._embedding_backend.embed(text)

    def _retrieve_by_embedding(
        self, query_vec: List[float], limit: int
    ) -> List[str]:
        scored: List[tuple[float, str]] = []
        cosine = EmbeddingBackend.cosine_similarity

        for i, memory in enumerate(self.episodic_memories):
            summary = str(memory.get("summary", "")).strip()
            if not summary:
                continue
            vec = (
                self._episodic_embeddings[i]
                if i < len(self._episodic_embeddings)
                else None
            )
            if vec is None:
                vec = self._embed(summary)
                # Backfill so future calls don't re-embed
                if i < len(self._episodic_embeddings):
                    self._episodic_embeddings[i] = vec
            if vec is None:
                continue
            sim = cosine(query_vec, vec)
            # Apply recency boost (same 20% cap as BM25 path)
            recency = (i + 1) / max(len(self.episodic_memories), 1)
            scored.append((sim * (1 + 0.2 * recency), f"Episodic: {summary}"))

        for i, fact in enumerate(self.semantic_facts):
            vec = (
                self._semantic_embeddings[i]
                if i < len(self._semantic_embeddings)
                else None
            )
            if vec is None:
                vec = self._embed(fact)
                if i < len(self._semantic_embeddings):
                    self._semantic_embeddings[i] = vec
            if vec is None:
                continue
            sim = cosine(query_vec, vec)
            scored.append((sim, f"Semantic: {fact}"))

        scored.sort(key=lambda x: x[0], reverse=True)
        return self._deduplicate(scored, limit)

    def _retrieve_by_bm25(self, query: str, limit: int) -> List[str]:
        """BM25 fallback used when embedding backend is unavailable."""
        query_tokens = self._tokens_list(query)
        if not query_tokens:
            return []
        scored: List[tuple[float, str]] = []

        for i, memory in enumerate(self.episodic_memories):
            summary = str(memory.get("summary", "")).strip()
            if not summary:
                continue
            score = self._bm25_score(query_tokens, self._tokens_list(summary))
            if score > 0:
                recency = (i + 1) / max(len(self.episodic_memories), 1)
                scored.append((score * (1 + 0.2 * recency), f"Episodic: {summary}"))

        for fact in self.semantic_facts:
            score = self._bm25_score(query_tokens, self._tokens_list(fact))
            if score > 0:
                scored.append((score, f"Semantic: {fact}"))

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

    # ------------------------------------------------------------------
    # Internal — limits and summary
    # ------------------------------------------------------------------

    def _enforce_limits(self):
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

    def _enforce_long_term_limits(self):
        if len(self.episodic_memories) > self.max_episodic_items:
            trim = len(self.episodic_memories) - self.max_episodic_items
            self.episodic_memories = self.episodic_memories[trim:]
            self._episodic_embeddings = self._episodic_embeddings[trim:]
        if len(self.semantic_facts) > self.max_semantic_facts:
            trim = len(self.semantic_facts) - self.max_semantic_facts
            self.semantic_facts = self.semantic_facts[trim:]
            self._semantic_embeddings = self._semantic_embeddings[trim:]

    # Internal — BM25 (kept as fallback)

    @staticmethod
    def _tokens_list(text: str) -> list[str]:
        return [t.lower() for t in re.findall(r"[a-zA-Z0-9_.:-]{2,}", text or "")]

    @staticmethod
    def _bm25_score(
        query_tokens: list[str],
        doc_tokens: list[str],
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
            idf = math.log(1 + (1 / (tf + 0.5)))
            tf_norm = (tf * (k1 + 1)) / (
                tf + k1 * (1 - b + b * (doc_len / avg_doc_len))
            )
            score += idf * tf_norm
        return score

    # kept for backwards compat
    @staticmethod
    def _token_overlap_score(query_tokens: set[str], text_tokens: set[str]) -> float:
        if not query_tokens or not text_tokens:
            return 0.0
        return len(query_tokens & text_tokens) / max(len(query_tokens), 1)

    # ------------------------------------------------------------------
    # Internal — tagging / fact extraction
    # ------------------------------------------------------------------

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
            if any(
                marker in lowered
                for marker in ("severity", "confidence", "ioc", "#chunk-")
            ):
                facts.append(line[:240])
        return facts[:6]