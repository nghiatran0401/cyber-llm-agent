"""RAG helpers wired to the integrated Chroma-backed MITRE retrieval.

This module now enforces a single RAGResult contract for all retrieval
callers and tool interfaces. Retrieval never raises; it returns structured
status objects and formatted strings for LLM consumption.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import List, Literal

from langchain_core.tools import Tool

from src.config.settings import Settings
from src.rag.data_models import RetrievedContext
from src.rag.ingestion.index_builder import build_mitre_index
from src.rag.retrieval.retriever import retrieve_mitre_contexts
from src.rag.retrieval.reranker import simple_rerank
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


# -------------------------
# Contract definitions
# -------------------------

StatusType = Literal["ok", "no_results", "error"]


@dataclass
class RAGChunk:
    text: str
    source_file: str
    chunk_id: str
    score: float


@dataclass
class RAGResult:
    query: str
    status: StatusType
    chunks: List[RAGChunk]
    citations: List[str]
    scores: List[float]
    error_message: str | None = None
    retrieval_latency_ms: float | None = None


def ingest_knowledge_base() -> str:
    """Build or refresh the MITRE Chroma index."""
    if not Settings.ENABLE_RAG:
        return "RAG is disabled."
    try:
        build_mitre_index()
        return "MITRE RAG index build completed."
    except Exception as exc:  # pragma: no cover
        logger.error("RAG ingestion failed: %s", exc, exc_info=True)
        return f"RAG ingestion failed: {exc}"


def _build_chunks(raw_contexts: List[RetrievedContext]) -> List[RAGChunk]:
    chunks: List[RAGChunk] = []
    for idx, ctx in enumerate(raw_contexts):
        meta = ctx.metadata or {}
        source = meta.get("source") or meta.get("source_file") or "unknown"
        chunk_id = meta.get("chunk_id") or meta.get("id") or f"chunk_{idx}"
        chunks.append(
            RAGChunk(
                text=ctx.document,
                source_file=source,
                chunk_id=str(chunk_id),
                score=float(ctx.score),
            )
        )
    return chunks


def _make_result(
    *,
    query: str,
    status: StatusType,
    chunks: List[RAGChunk] | None = None,
    error_message: str | None = None,
    latency_ms: float | None = None,
) -> RAGResult:
    chunks = chunks or []
    citations = [f"{c.source_file}#{c.chunk_id}" for c in chunks]
    scores = [c.score for c in chunks]
    return RAGResult(
        query=query,
        status=status,
        chunks=chunks,
        citations=citations,
        scores=scores,
        error_message=error_message,
        retrieval_latency_ms=latency_ms,
    )


def format_rag_result(result: RAGResult) -> str:
    """Human/LLM-friendly rendering of a RAGResult."""
    if result.status == "error":
        return f"RAG retrieval error: {result.error_message or 'unknown error'}"
    if result.status == "no_results":
        return "No relevant context found in knowledge base."

    lines = ["Retrieved Context (source=chroma):"]
    for i, chunk in enumerate(result.chunks, start=1):
        lines.append(
            f"- Match {i} [score={chunk.score:.4f}] "
            f"[source={chunk.source_file}#{chunk.chunk_id}]: {chunk.text}"
        )
    if result.citations:
        lines.append("Citations:")
        for citation in sorted(set(result.citations)):
            lines.append(f"- {citation}")
    return "\n".join(lines)


def retrieve_security_context(query: str) -> RAGResult:
    """
    Retrieve top MITRE contexts from the local Chroma index.

    Returns a RAGResult with status one of {"ok", "no_results", "error"}.
    Never raises; callers can rely on structured status and error_message.
    """

    start = time.perf_counter()
    clean_query = (query or "").strip()
    if not clean_query:
        return _make_result(query=clean_query, status="no_results", error_message="Empty query.")
    if not Settings.ENABLE_RAG:
        return _make_result(query=clean_query, status="error", error_message="RAG is disabled.")

    try:
        contexts = retrieve_mitre_contexts(clean_query)
        latency_ms = (time.perf_counter() - start) * 1000
        if not contexts:
            logger.debug("RAG no_results query=%s latency_ms=%.2f", clean_query, latency_ms)
            return _make_result(query=clean_query, status="no_results", latency_ms=latency_ms)

        ranked = simple_rerank(contexts)

        # Apply minimum score threshold (higher is better after rerank conversion)
        min_score = getattr(Settings, "RAG_MIN_SCORE", 0.25)
        filtered = [c for c in ranked if c.score >= min_score]

        if not filtered:
            logger.warning(
                "RAG below-threshold query=%s min_score=%.2f latency_ms=%.2f",
                clean_query,
                min_score,
                latency_ms,
            )
            return _make_result(query=clean_query, status="no_results", latency_ms=latency_ms)

        top = filtered[: Settings.RAG_MAX_RESULTS]
        chunks = _build_chunks(top)
        result = _make_result(query=clean_query, status="ok", chunks=chunks, latency_ms=latency_ms)
        avg_score = sum(result.scores) / len(result.scores)
        logger.debug(
            "RAG ok query=%s latency_ms=%.2f num_chunks=%d avg_score=%.4f",  # noqa: W605
            clean_query,
            latency_ms,
            len(chunks),
            avg_score,
        )
        return result
    except Exception as exc:  # pragma: no cover
        latency_ms = (time.perf_counter() - start) * 1000
        logger.error("RAG retrieval failed: %s", exc, exc_info=True)
        return _make_result(query=clean_query, status="error", error_message=str(exc), latency_ms=latency_ms)


rag_ingest = Tool(
    name="RAGIngest",
    func=ingest_knowledge_base,
    description="Builds the local MITRE ATT&CK Chroma index for RAG.",
)


def _rag_tool_wrapper(query: str) -> str:
    """LangChain Tool wrapper that returns formatted text for the LLM."""
    return format_rag_result(retrieve_security_context(query))


rag_retriever = Tool(
    name="RAGRetriever",
    func=_rag_tool_wrapper,
    description="Retrieves MITRE/knowledge-base context from the local Chroma index (returns citations and scores).",
)
