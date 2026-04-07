from __future__ import annotations

import math
from typing import List, Optional

from langchain_openai import OpenAIEmbeddings

from src.config.settings import Settings
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


def create_openai_embeddings() -> OpenAIEmbeddings:
    return OpenAIEmbeddings(
        model=Settings.OPENAI_EMBEDDING_MODEL,
        openai_api_key=Settings.OPENAI_API_KEY,
    )


class EmbeddingMemory:
    """OpenAI embedding vectors for memory recall via LangChain ``OpenAIEmbeddings``.
    """

    def __init__(
        self,
        openai_model: str = "text-embedding-3-small",
        *,
        openai_api_key: str | None = None,
    ):
        self.openai_model = openai_model
        self._openai_api_key = openai_api_key
        self._lc_embeddings: Optional[OpenAIEmbeddings] = None

    def embed(self, text: str) -> Optional[List[float]]:
        """Return an embedding vector, or None if input is empty or call fails."""
        if not (text or "").strip():
            return None
        try:
            return self._embed_openai(text)
        except Exception as exc:
            logger.warning("Embedding failed (openai): %s", exc)
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
        """Construct from application :class:`Settings`."""
        return cls(
            openai_model=Settings.OPENAI_EMBEDDING_MODEL,
            openai_api_key=Settings.OPENAI_API_KEY,
        )

    def _ensure_lc_embeddings(self) -> OpenAIEmbeddings:
        if self._lc_embeddings is None:
            key = self._openai_api_key if self._openai_api_key is not None else Settings.OPENAI_API_KEY
            self._lc_embeddings = OpenAIEmbeddings(
                model=self.openai_model,
                openai_api_key=key,
            )
        return self._lc_embeddings

    def _embed_openai(self, text: str) -> List[float]:
        embeddings = self._ensure_lc_embeddings()
        # Match typical single-string retrieval usage (same path semantics as RAG queries).
        vector = embeddings.embed_query((text or "")[:8000])
        return list(vector)
