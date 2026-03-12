"""Unit tests for integrated RAG tools (Chroma-backed)."""

from types import SimpleNamespace

import src.tools.rag_tools as rag_tools


def test_rag_ingest_uses_mitre_index(monkeypatch):
    called = {}

    def fake_build():
        called["ingest"] = True

    monkeypatch.setattr(rag_tools, "build_mitre_index", fake_build)
    monkeypatch.setattr("src.tools.rag_tools.Settings.ENABLE_RAG", True)

    msg = rag_tools.ingest_knowledge_base()
    assert called.get("ingest")
    assert "completed" in msg.lower()


def test_rag_retrieve_formats_results(monkeypatch):
    fake_ctx = [
        SimpleNamespace(
            document="Example text",
            metadata={"source": "data/mitre/T0000.md"},
            score=0.12,
        )
    ]

    monkeypatch.setattr(rag_tools, "retrieve_mitre_contexts", lambda q: fake_ctx)
    monkeypatch.setattr(rag_tools, "simple_rerank", lambda ctxs: ctxs)
    monkeypatch.setattr("src.tools.rag_tools.Settings.ENABLE_RAG", True)
    monkeypatch.setattr("src.tools.rag_tools.Settings.RAG_MAX_RESULTS", 3)

    out = rag_tools.retrieve_security_context("anything")
    assert "Retrieved Context" in out
    assert "Citations:" in out
    assert "data/mitre/T0000.md" in out


def test_rag_retrieve_empty(monkeypatch):
    monkeypatch.setattr(rag_tools, "retrieve_mitre_contexts", lambda q: [])
    monkeypatch.setattr("src.tools.rag_tools.Settings.ENABLE_RAG", True)

    out = rag_tools.retrieve_security_context("anything")
    assert "No relevant context" in out
