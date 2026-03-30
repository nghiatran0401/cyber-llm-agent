"""Unit tests for RAG tools with mocked Pinecone backend."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from src.tools.rag_tools import ingest_knowledge_base, retrieve_security_context


def test_rag_ingest_and_retrieve(monkeypatch, tmp_path: Path):
    knowledge_dir = tmp_path / "knowledge"
    knowledge_dir.mkdir(parents=True, exist_ok=True)
    (knowledge_dir / "note.md").write_text(
        "Brute force attacks include repeated failed login attempts from one source IP.",
        encoding="utf-8",
    )

    monkeypatch.setattr("src.tools.rag_tools.Settings.ENABLE_RAG", True)
    monkeypatch.setattr("src.tools.rag_tools.Settings.KNOWLEDGE_DIR", knowledge_dir)
    monkeypatch.setattr("src.tools.rag_tools.Settings.BASE_DIR", tmp_path)
    monkeypatch.setattr("src.tools.rag_tools.Settings.PINECONE_API_KEY", "fake-key")
    monkeypatch.setattr("src.tools.rag_tools.Settings.PINECONE_INDEX_NAME", "test-index")
    monkeypatch.setattr("src.tools.rag_tools.Settings.OPENAI_API_KEY", "fake-key")
    monkeypatch.setattr("src.tools.rag_tools.Settings.RAG_MAX_RESULTS", 2)

    mock_pc = MagicMock()
    mock_pc.list_indexes.return_value = [{"name": "test-index"}]
    monkeypatch.setattr("src.tools.rag_tools._get_pinecone_client", lambda: mock_pc)

    mock_doc = MagicMock()
    mock_doc.page_content = "Brute force attacks include repeated failed login attempts."
    mock_doc.metadata = {"source": str(knowledge_dir / "note.md")}

    with patch("src.tools.rag_tools.DirectoryLoader") as mock_loader_cls, \
         patch("src.tools.rag_tools.PineconeVectorStore") as mock_vs_cls, \
         patch("src.tools.rag_tools.OpenAIEmbeddings") as mock_embed_cls:
        mock_loader_cls.return_value.load.return_value = [mock_doc]
        mock_embed_cls.return_value = MagicMock()
        mock_vs_cls.from_documents.return_value = MagicMock()
        ingest_result = ingest_knowledge_base()

    assert "chunks" in ingest_result.lower() or "processed" in ingest_result.lower()

    mock_doc = MagicMock()
    mock_doc.page_content = "Brute force attacks include repeated failed login attempts."
    mock_doc.metadata = {"source": str(knowledge_dir / "note.md")}

    with patch("src.tools.rag_tools.PineconeVectorStore") as mock_vs_cls, \
         patch("src.tools.rag_tools.OpenAIEmbeddings") as mock_embed_cls:
        mock_embed_cls.return_value = MagicMock()
        mock_retriever = MagicMock()
        mock_retriever.invoke.return_value = [mock_doc]
        mock_vs_cls.return_value.as_retriever.return_value = mock_retriever
        retrieved = retrieve_security_context("failed login brute force")

    assert "Retrieved Context" in retrieved
    assert "Citations:" in retrieved


def test_rag_retrieve_empty_index(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("src.tools.rag_tools.Settings.ENABLE_RAG", True)
    monkeypatch.setattr("src.tools.rag_tools.Settings.KNOWLEDGE_DIR", tmp_path)
    monkeypatch.setattr("src.tools.rag_tools.Settings.BASE_DIR", tmp_path)
    monkeypatch.setattr("src.tools.rag_tools.Settings.PINECONE_API_KEY", "fake-key")
    monkeypatch.setattr("src.tools.rag_tools.Settings.PINECONE_INDEX_NAME", "test-index")
    monkeypatch.setattr("src.tools.rag_tools.Settings.OPENAI_API_KEY", "fake-key")
    monkeypatch.setattr("src.tools.rag_tools.Settings.RAG_MAX_RESULTS", 2)

    with patch("src.tools.rag_tools.PineconeVectorStore") as mock_vs_cls, \
         patch("src.tools.rag_tools.OpenAIEmbeddings") as mock_embed_cls:
        mock_embed_cls.return_value = MagicMock()
        mock_retriever = MagicMock()
        mock_retriever.invoke.return_value = []
        mock_vs_cls.return_value.as_retriever.return_value = mock_retriever
        result = retrieve_security_context("ransomware ioc")

    assert "No relevant context" in result


def test_rag_citation_format(monkeypatch, tmp_path: Path):
    knowledge_dir = tmp_path / "knowledge"
    knowledge_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr("src.tools.rag_tools.Settings.ENABLE_RAG", True)
    monkeypatch.setattr("src.tools.rag_tools.Settings.KNOWLEDGE_DIR", knowledge_dir)
    monkeypatch.setattr("src.tools.rag_tools.Settings.BASE_DIR", tmp_path)
    monkeypatch.setattr("src.tools.rag_tools.Settings.PINECONE_API_KEY", "fake-key")
    monkeypatch.setattr("src.tools.rag_tools.Settings.PINECONE_INDEX_NAME", "test-index")
    monkeypatch.setattr("src.tools.rag_tools.Settings.OPENAI_API_KEY", "fake-key")
    monkeypatch.setattr("src.tools.rag_tools.Settings.RAG_MAX_RESULTS", 2)

    mock_doc = MagicMock()
    mock_doc.page_content = "Ransomware response requires host isolation and credential rotation."
    mock_doc.metadata = {"source": str(knowledge_dir / "ops.md")}

    with patch("src.tools.rag_tools.PineconeVectorStore") as mock_vs_cls, \
         patch("src.tools.rag_tools.OpenAIEmbeddings") as mock_embed_cls:
        mock_embed_cls.return_value = MagicMock()
        mock_retriever = MagicMock()
        mock_retriever.invoke.return_value = [mock_doc]
        mock_vs_cls.return_value.as_retriever.return_value = mock_retriever
        retrieved = retrieve_security_context("ransomware isolation steps")

    assert "Citations:" in retrieved
    citation_lines = [line for line in retrieved.splitlines() if line.startswith("- ") and "ops.md" in line]
    assert citation_lines
