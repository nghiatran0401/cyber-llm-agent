import hashlib
from unittest.mock import MagicMock

from src.utils.embedding import EmbeddingMemory
from src.utils.memory_manager import ConversationMemory


# ------------------------------------------------------------------
# Shared helpers
# ------------------------------------------------------------------

def _fake_embedding(text: str) -> list[float]:
    """Deterministic fake embedding: MD5 digest mapped to an 8-dim vector.

    Intentionally short (production vectors are 1536+ dims); cosine_similarity
    only requires equal lengths between query and document vectors from this stub.
    """
    digest = hashlib.md5(text.encode()).digest()
    return [((b / 255.0) * 2 - 1) for b in digest[:8]]


def _make_memory_with_fake_embeddings() -> ConversationMemory:
    """Memory wired to a deterministic fake backend — no real API calls."""
    backend = EmbeddingMemory(enabled=True)
    backend.embed = _fake_embedding  # type: ignore[method-assign]
    memory = ConversationMemory(memory_type="buffer", max_messages=6, recall_top_k=3)
    memory._embedding_backend = backend
    return memory


# ------------------------------------------------------------------
# OpenAI provider
# ------------------------------------------------------------------

def test_embedding_memory_openai_returns_vector():
    backend = EmbeddingMemory(enabled=True)
    mock_lc = MagicMock()
    mock_lc.embed_query.return_value = [0.1, 0.2, 0.3]
    backend._lc_embeddings = mock_lc

    result = backend.embed("test query")

    assert result == [0.1, 0.2, 0.3]
    mock_lc.embed_query.assert_called_once()


# ------------------------------------------------------------------
# Disabled / failure paths
# ------------------------------------------------------------------

def test_embedding_memory_disabled_returns_none():
    backend = EmbeddingMemory(enabled=False)
    assert backend.embed("anything") is None


def test_embedding_memory_empty_text_returns_none():
    backend = EmbeddingMemory(enabled=True)
    assert backend.embed("") is None
    assert backend.embed("   ") is None


def test_embedding_memory_failure_returns_none_not_raises():
    backend = EmbeddingMemory(enabled=True)
    mock_lc = MagicMock()
    mock_lc.embed_query.side_effect = RuntimeError("network error")
    backend._lc_embeddings = mock_lc
    # Must not raise — falls back gracefully so callers can switch to BM25
    assert backend.embed("query that fails") is None


# ------------------------------------------------------------------
# Cosine similarity
# ------------------------------------------------------------------

def test_cosine_similarity_identical_vectors():
    v = [0.1, 0.5, 0.3]
    assert abs(EmbeddingMemory.cosine_similarity(v, v) - 1.0) < 1e-6


def test_cosine_similarity_orthogonal_vectors():
    assert abs(EmbeddingMemory.cosine_similarity([1.0, 0.0], [0.0, 1.0])) < 1e-6


def test_cosine_similarity_zero_vector_returns_zero():
    assert EmbeddingMemory.cosine_similarity([0.0, 0.0], [1.0, 2.0]) == 0.0


def test_cosine_similarity_mismatched_lengths_returns_zero():
    assert EmbeddingMemory.cosine_similarity([1.0, 2.0], [1.0]) == 0.0


# ------------------------------------------------------------------
# Integration with ConversationMemory
# ------------------------------------------------------------------

def test_recall_uses_embedding_path_when_available():
    memory = _make_memory_with_fake_embeddings()
    memory.update_long_term_from_turn(
        "ransomware C2 beacon to external IP",
        "Severity: critical\nIOC: 10.0.0.1\nSource: VirusTotal",
    )
    memory.update_long_term_from_turn(
        "patch schedule review",
        "Recommended Actions:\n- Apply CVE-2024-1234",
    )
    recalled = memory.retrieve_relevant_memories("ransomware C2 beacon")
    assert isinstance(recalled, list)
    assert all(isinstance(item, str) for item in recalled)


def test_recall_falls_back_to_bm25_when_embedding_disabled():
    backend = EmbeddingMemory(enabled=False)
    memory = ConversationMemory(memory_type="buffer", max_messages=6, recall_top_k=3)
    memory._embedding_backend = backend
    memory.update_long_term_from_turn(
        "failed login brute force VPN gateway",
        "Severity: high\n- 400 SSH attempts from 185.0.0.2",
    )
    recalled = memory.retrieve_relevant_memories("failed login VPN")
    assert recalled
    assert any("failed" in item.lower() or "login" in item.lower() for item in recalled)


def test_load_state_reembeds_entries():
    """Embeddings must be rebuilt from text after a session round-trip."""
    memory = _make_memory_with_fake_embeddings()
    memory.add_episodic_memory("phishing email detected on endpoint A", tags=["phishing"])
    memory.add_semantic_fact("Severity: high — confirmed phishing campaign")
    state = memory.get_state()

    # Embeddings must NOT appear in persisted state
    assert "episodic_embeddings" not in state
    assert "semantic_embeddings" not in state

    # Restore into a fresh instance with the same fake backend
    memory2 = _make_memory_with_fake_embeddings()
    memory2.load_state(
        messages=state["messages"],
        running_summary=state["running_summary"],
        episodic_memories=state["episodic_memories"],
        semantic_facts=state["semantic_facts"],
    )
    assert len(memory2._episodic_embeddings) == len(memory2.episodic_memories)
    assert len(memory2._semantic_embeddings) == len(memory2.semantic_facts)
    assert memory2._episodic_embeddings[0] is not None
