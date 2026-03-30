"""Unit tests for RAG tools (Pinecone-backed implementation)."""

from pathlib import Path
from unittest.mock import MagicMock

from src.tools import rag_tools
from src.tools.rag_tools import ingest_knowledge_base, retrieve_security_context


def test_retrieve_security_context_empty_query():
    out = retrieve_security_context("   ")
    assert "empty" in out.lower()


def test_ingest_knowledge_base_no_documents(tmp_path: Path, monkeypatch):
    knowledge = tmp_path / "knowledge"
    knowledge.mkdir()
    monkeypatch.setattr(rag_tools.Settings, "KNOWLEDGE_DIR", knowledge)
    assert "No valid documents" in ingest_knowledge_base()


def test_retrieve_security_context_pinecone_success(monkeypatch):
    """Smoke path: vectorstore returns docs; no real Pinecone/OpenAI calls."""
    monkeypatch.setattr(rag_tools.Settings, "RAG_MAX_RESULTS", 2)
    monkeypatch.setattr(rag_tools.Settings, "PINECONE_INDEX_NAME", "test-index")
    monkeypatch.setattr(rag_tools.Settings, "OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(rag_tools.Settings, "BASE_DIR", rag_tools.Settings.BASE_DIR)

    doc = MagicMock()
    doc.metadata = {"source": str(rag_tools.Settings.BASE_DIR / "data" / "knowledge" / "note.md")}
    doc.page_content = "Brute force means repeated failed logins."

    mock_vs = MagicMock()
    mock_vs.as_retriever.return_value.invoke.return_value = [doc]

    monkeypatch.setattr(rag_tools, "OpenAIEmbeddings", MagicMock(return_value=MagicMock()))
    monkeypatch.setattr(rag_tools, "PineconeVectorStore", MagicMock(return_value=mock_vs))

    out = retrieve_security_context("failed login brute force")
    assert "Retrieved Context (mode=pinecone_semantic):" in out
    assert "Citations:" in out
    assert "Brute force" in out
