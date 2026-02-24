"""Unit tests for basic local RAG tools."""

from pathlib import Path

from src.tools.rag_tools import ingest_knowledge_base, retrieve_security_context


def test_rag_ingest_and_retrieve(monkeypatch, tmp_path: Path):
    knowledge_dir = tmp_path / "knowledge"
    knowledge_dir.mkdir(parents=True, exist_ok=True)
    (knowledge_dir / "note.md").write_text(
        "Brute force attacks include repeated failed login attempts from one source IP.",
        encoding="utf-8",
    )

    monkeypatch.setattr("src.tools.rag_tools.Settings.KNOWLEDGE_DIR", knowledge_dir)
    monkeypatch.setattr("src.tools.rag_tools.Settings.BASE_DIR", tmp_path)
    monkeypatch.setattr("src.tools.rag_tools.Settings.RAG_CHUNK_SIZE", 20)
    monkeypatch.setattr("src.tools.rag_tools.Settings.RAG_MAX_RESULTS", 2)
    monkeypatch.setattr("src.tools.rag_tools._RAG_INDEX_PATH", knowledge_dir / "rag_index.json")

    ingest_result = ingest_knowledge_base()
    retrieved = retrieve_security_context("failed login brute force")

    assert "chunks=" in ingest_result
    assert "Retrieved Context:" in retrieved
    assert "Citations:" in retrieved
