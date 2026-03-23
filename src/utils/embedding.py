from __future__ import annotations

import json as _json
import math
import urllib.request
from typing import List, Optional

from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class EmbeddingMemory:
    """Thin wrapper that returns float vectors from either OpenAI or Ollama.

    Construct directly for tests, or use ``from_settings()`` for production.
    Returns ``None`` on any provider error so callers fall back to BM25
    without crashing.
    """

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
            raise ValueError(
                f"EmbeddingBackend provider must be one of {allowed}; got '{provider}'."
            )
        self.provider = provider
        self.openai_model = openai_model
        self.ollama_base_url = ollama_base_url.rstrip("/")
        self.ollama_model = ollama_model
        self.enabled = enabled
        self._openai_client = None  # lazy-init — avoids OpenAI import cost at module load

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def embed(self, text: str) -> Optional[List[float]]:
        """Return an embedding vector, or None if disabled or the call fails."""
        if not self.enabled or not (text or "").strip():
            return None
        try:
            if self.provider == "openai":
                return self._embed_openai(text)
            return self._embed_ollama(text)
        except Exception as exc:
            logger.warning(
                "Embedding failed (%s), falling back to BM25: %s", self.provider, exc
            )
            return None

    @staticmethod
    def cosine_similarity(a: List[float], b: List[float]) -> float:
        """Cosine similarity between two equal-length vectors. Returns 0.0 on bad input."""
        if not a or not b or len(a) != len(b):
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0
        return dot / (norm_a * norm_b)

    @classmethod
    def from_settings(cls) -> "EmbeddingMemory":
        """Construct from Settings. Deferred import avoids circular dependency."""
        from src.config.settings import Settings

        return cls(
            provider=Settings.EMBEDDING_PROVIDER,
            openai_model=Settings.OPENAI_EMBEDDING_MODEL,
            ollama_base_url=Settings.OLLAMA_BASE_URL,
            ollama_model=Settings.OLLAMA_EMBEDDING_MODEL,
            enabled=Settings.EMBEDDING_ENABLED,
        )

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _embed_openai(self, text: str) -> List[float]:
        if self._openai_client is None:
            from openai import OpenAI
            self._openai_client = OpenAI()
        response = self._openai_client.embeddings.create(
            input=text[:8000],
            model=self.openai_model,
        )
        return response.data[0].embedding

    def _embed_ollama(self, text: str) -> List[float]:
        payload = _json.dumps(
            {"model": self.ollama_model, "prompt": text[:8000]}
        ).encode()
        req = urllib.request.Request(
            f"{self.ollama_base_url}/api/embeddings",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = _json.loads(resp.read().decode())
        return result["embedding"]