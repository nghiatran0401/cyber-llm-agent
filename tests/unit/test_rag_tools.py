"""Unit tests for integrated RAG tools (Chroma-backed)."""

from types import SimpleNamespace

import src.tools.rag_tools as rag_tools


def _ctx(score: float = 0.9, source: str = "data/mitre/T0000.md", chunk_id: str = "ID0"):
    return SimpleNamespace(
        document="Example text",
        metadata={"source": source, "chunk_id": chunk_id},
        score=score,
    )


def test_rag_ingest_uses_mitre_index(monkeypatch):
    called = {}

    def fake_build():
        called["ingest"] = True

    monkeypatch.setattr(rag_tools, "build_mitre_index", fake_build)
    monkeypatch.setattr("src.tools.rag_tools.Settings.ENABLE_RAG", True)

    msg = rag_tools.ingest_knowledge_base()
    assert called.get("ingest")
    assert "completed" in msg.lower()


def test_rag_retrieve_returns_contract(monkeypatch):
    fake_ctx = [_ctx(score=0.8)]
    monkeypatch.setattr(rag_tools, "retrieve_mitre_contexts", lambda q: fake_ctx)
    monkeypatch.setattr(rag_tools, "simple_rerank", lambda ctxs: ctxs)
    monkeypatch.setattr("src.tools.rag_tools.Settings.ENABLE_RAG", True)
    monkeypatch.setattr("src.tools.rag_tools.Settings.RAG_MAX_RESULTS", 3)

    result = rag_tools.retrieve_security_context("anything")

    assert result.status == "ok"
    assert result.chunks, "chunks should not be empty on success"
    assert result.citations[0].startswith("data/mitre/T0000.md#")
    assert result.scores[0] == fake_ctx[0].score

    formatted = rag_tools.format_rag_result(result)
    assert "Retrieved Context" in formatted
    assert "Citations:" in formatted


def test_rag_retrieve_no_results(monkeypatch):
    monkeypatch.setattr(rag_tools, "retrieve_mitre_contexts", lambda q: [])
    monkeypatch.setattr("src.tools.rag_tools.Settings.ENABLE_RAG", True)

    result = rag_tools.retrieve_security_context("anything")
    assert result.status == "no_results"
    assert result.chunks == []


def test_rag_retrieve_below_threshold(monkeypatch):
    fake_ctx = [_ctx(score=0.1)]
    monkeypatch.setattr(rag_tools, "retrieve_mitre_contexts", lambda q: fake_ctx)
    monkeypatch.setattr(rag_tools, "simple_rerank", lambda ctxs: ctxs)
    monkeypatch.setattr("src.tools.rag_tools.Settings.ENABLE_RAG", True)
    monkeypatch.setattr("src.tools.rag_tools.Settings.RAG_MIN_SCORE", 0.25)

    result = rag_tools.retrieve_security_context("anything")
    assert result.status == "no_results"


def test_rag_retrieve_error(monkeypatch):
    def boom(_):
        raise RuntimeError("fail")

    monkeypatch.setattr(rag_tools, "retrieve_mitre_contexts", boom)
    monkeypatch.setattr("src.tools.rag_tools.Settings.ENABLE_RAG", True)

    result = rag_tools.retrieve_security_context("anything")
    assert result.status == "error"
    assert "fail" in (result.error_message or "")
