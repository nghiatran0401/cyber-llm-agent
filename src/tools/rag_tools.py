"""RAG helpers wired to the integrated Chroma-backed MITRE retrieval."""

from __future__ import annotations

from typing import List

from langchain_core.tools import Tool

from src.config.settings import Settings
from src.rag.data_models import RetrievedContext
from src.rag.ingestion.index_builder import build_mitre_index
from src.rag.retrieval.retriever import retrieve_mitre_contexts
from src.rag.retrieval.reranker import simple_rerank
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


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


def _format_contexts(contexts: List[RetrievedContext]) -> str:
    lines = ["Retrieved Context (source=chroma):"]
    citations = []
    for i, ctx in enumerate(contexts, start=1):
        source = ctx.metadata.get("source", "unknown")
        lines.append(f"- Match {i} [score={ctx.score:.4f}] [source={source}]: {ctx.document}")
        citations.append(source)
    if citations:
        lines.append("Citations:")
        for c in sorted(set(citations)):
            lines.append(f"- {c}")
    return "\n".join(lines)


def retrieve_security_context(query: str) -> str:
    """Retrieve top MITRE contexts from the local Chroma index."""
    clean_query = (query or "").strip()
    if not clean_query:
        return "No retrieval performed because query is empty."
    if not Settings.ENABLE_RAG:
        return "RAG is disabled."

    try:
        contexts = retrieve_mitre_contexts(clean_query)
        if not contexts:
            return "No relevant context found in MITRE knowledge base."
        ranked = simple_rerank(contexts)
        return _format_contexts(ranked[: Settings.RAG_MAX_RESULTS])
    except Exception as exc:  # pragma: no cover
        logger.error("RAG retrieval failed: %s", exc, exc_info=True)
        return f"Retrieval failed due to an error: {exc}"


rag_ingest = Tool(
    name="RAGIngest",
    func=ingest_knowledge_base,
    description="Builds the local MITRE ATT&CK Chroma index for RAG.",
)

rag_retriever = Tool(
    name="RAGRetriever",
    func=retrieve_security_context,
    description="Retrieves MITRE ATT&CK context from the local Chroma index.",
)
