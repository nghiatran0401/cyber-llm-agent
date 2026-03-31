"""RAG helpers: Pinecone (default) or optional local Chroma + MITRE markdown.

``RAG_VECTOR_BACKEND`` selects the stack:
- ``pinecone``: LangChain + OpenAI embeddings over ``data/knowledge`` (cloud index).
- ``chroma``: sentence-transformers + Chroma over ``RAG_DATA_PATH`` (typically MITRE .md files).

Tool entrypoints return human-readable strings; use ``get_rag_result`` for structured access.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Literal

from langchain_core.tools import Tool
from langchain_community.document_loaders import DirectoryLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
from langchain_pinecone import PineconeVectorStore
from pinecone import Pinecone, ServerlessSpec

from src.config.settings import Settings
from src.rag.config import reset_rag_config_cache
from src.utils.logger import setup_logger

logger = setup_logger(__name__)

_ALLOWED_SUFFIXES = {".txt", ".md", ".log", ".json", ".jsonl"}

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


def _use_chroma_backend() -> bool:
    return Settings.RAG_VECTOR_BACKEND == "chroma"


def _sync_chroma_env_from_app() -> None:
    """Align subprocess RAG config with ``src.config.settings.Settings``."""
    os.environ["RAG_DATA_PATH"] = str(Settings.RAG_DATA_PATH)
    os.environ["RAG_CHROMA_PATH"] = str(Settings.RAG_CHROMA_PATH)
    os.environ["RAG_CHROMA_COLLECTION"] = Settings.RAG_CHROMA_COLLECTION
    os.environ["RAG_EMBEDDING_MODEL"] = Settings.RAG_EMBEDDING_MODEL
    os.environ["RAG_TOP_K"] = str(Settings.RAG_TOP_K)
    os.environ["RAG_DISTANCE_THRESHOLD"] = str(Settings.RAG_DISTANCE_THRESHOLD)
    reset_rag_config_cache()


def _get_pinecone_client() -> Pinecone:
    if not Settings.PINECONE_API_KEY:
        raise ValueError("PINECONE_API_KEY is not set.")
    return Pinecone(api_key=Settings.PINECONE_API_KEY)


def ingest_knowledge_base() -> str:
    """Build or refresh the active RAG index (Pinecone or local Chroma)."""
    if not Settings.ENABLE_RAG:
        return "RAG is disabled."

    if _use_chroma_backend():
        try:
            _sync_chroma_env_from_app()
            from src.rag.ingestion.index_builder import build_mitre_index

            build_mitre_index()
            return "MITRE RAG index build completed (Chroma)."
        except Exception as exc:  # pragma: no cover
            logger.error("Chroma RAG ingestion failed: %s", exc, exc_info=True)
            return f"RAG ingestion failed: {exc}"

    logger.info("Starting knowledge base ingestion to Pinecone...")
    pc = _get_pinecone_client()
    index_name = Settings.PINECONE_INDEX_NAME

    existing_indexes = [index_info["name"] for index_info in pc.list_indexes()]
    if index_name not in existing_indexes:
        logger.info("Creating Pinecone index '%s'...", index_name)
        pc.create_index(
            name=index_name,
            dimension=1536,
            metric="cosine",
            spec=ServerlessSpec(cloud="aws", region="us-east-1"),
        )

    loader = DirectoryLoader(str(Settings.KNOWLEDGE_DIR), glob="**/*.*", show_progress=True)
    raw_docs = loader.load()
    docs = [
        doc
        for doc in raw_docs
        if Path(doc.metadata.get("source", "")).suffix.lower() in _ALLOWED_SUFFIXES
    ]

    if not docs:
        logger.info("No valid documents found for ingestion.")
        return "No valid documents found in data/knowledge."

    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=500,
        chunk_overlap=50,
        add_start_index=True,
    )
    chunks = text_splitter.split_documents(docs)
    embeddings = OpenAIEmbeddings(openai_api_key=Settings.OPENAI_API_KEY)

    logger.info("Uploading %s chunks to Pinecone index '%s'...", len(chunks), index_name)
    PineconeVectorStore.from_documents(chunks, embeddings, index_name=index_name)

    msg = f"RAG index refreshed using Pinecone. Processed {len(docs)} documents into {len(chunks)} chunks."
    logger.info(msg)
    return msg


def _build_chunks_from_pinecone_docs(docs) -> List[RAGChunk]:
    chunks: List[RAGChunk] = []
    for idx, doc in enumerate(docs, start=1):
        source = doc.metadata.get("source", "unknown")
        if str(Settings.BASE_DIR) in str(source):
            source = str(Path(source).relative_to(Settings.BASE_DIR))
        chunks.append(
            RAGChunk(
                text=doc.page_content,
                source_file=str(source),
                chunk_id=str(idx),
                score=max(0.0, 1.0 - (idx - 1) * 0.05),
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


def format_rag_result(result: RAGResult, *, source_label: str) -> str:
    """Human/LLM-friendly rendering of a RAGResult."""
    if result.status == "error":
        return f"RAG retrieval error: {result.error_message or 'unknown error'}"
    if result.status == "no_results":
        return "No relevant context found in knowledge base."

    lines = [f"Retrieved Context (source={source_label}):"]
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


def get_rag_result(query: str) -> RAGResult:
    """Structured retrieval for both backends (for benchmarks and tests)."""
    start = time.perf_counter()
    clean_query = (query or "").strip()
    if not clean_query:
        return _make_result(query=clean_query, status="no_results", error_message="Empty query.")
    if not Settings.ENABLE_RAG:
        return _make_result(query=clean_query, status="error", error_message="RAG is disabled.")

    if _use_chroma_backend():
        _sync_chroma_env_from_app()
        from src.rag.retrieval.reranker import simple_rerank
        from src.rag.retrieval.retriever import retrieve_mitre_contexts

        try:
            contexts = retrieve_mitre_contexts(clean_query)
            latency_ms = (time.perf_counter() - start) * 1000
            if not contexts:
                return _make_result(query=clean_query, status="no_results", latency_ms=latency_ms)

            ranked = simple_rerank(contexts)
            filtered = [c for c in ranked if c.score >= Settings.RAG_MIN_SCORE]
            if not filtered:
                return _make_result(query=clean_query, status="no_results", latency_ms=latency_ms)

            top = filtered[: Settings.RAG_MAX_RESULTS]
            chunks: List[RAGChunk] = []
            for idx, ctx in enumerate(top):
                meta = ctx.metadata or {}
                source = meta.get("source") or meta.get("source_file") or "unknown"
                chunk_id = meta.get("chunk_id") or meta.get("id") or f"chunk_{idx}"
                chunks.append(
                    RAGChunk(
                        text=ctx.document,
                        source_file=str(source),
                        chunk_id=str(chunk_id),
                        score=float(ctx.score),
                    )
                )
            return _make_result(query=clean_query, status="ok", chunks=chunks, latency_ms=latency_ms)
        except Exception as exc:  # pragma: no cover
            latency_ms = (time.perf_counter() - start) * 1000
            logger.error("Chroma RAG retrieval failed: %s", exc, exc_info=True)
            return _make_result(
                query=clean_query,
                status="error",
                error_message=str(exc),
                latency_ms=latency_ms,
            )

    try:
        embeddings = OpenAIEmbeddings(openai_api_key=Settings.OPENAI_API_KEY)
        vectorstore = PineconeVectorStore(
            index_name=Settings.PINECONE_INDEX_NAME,
            embedding=embeddings,
        )
        retriever = vectorstore.as_retriever(search_kwargs={"k": Settings.RAG_MAX_RESULTS})
        docs = retriever.invoke(clean_query)
        latency_ms = (time.perf_counter() - start) * 1000
        if not docs:
            return _make_result(query=clean_query, status="no_results", latency_ms=latency_ms)
        chunks = _build_chunks_from_pinecone_docs(docs)
        return _make_result(query=clean_query, status="ok", chunks=chunks, latency_ms=latency_ms)
    except Exception as exc:  # pragma: no cover
        latency_ms = (time.perf_counter() - start) * 1000
        logger.error("Pinecone RAG retrieval failed: %s", exc, exc_info=True)
        return _make_result(
            query=clean_query,
            status="error",
            error_message=str(exc),
            latency_ms=latency_ms,
        )


def retrieve_security_context(query: str) -> str:
    """LangChain tool entry: formatted retrieval string."""
    result = get_rag_result(query)
    label = "chroma" if _use_chroma_backend() else "pinecone_semantic"
    return format_rag_result(result, source_label=label)


rag_ingest = Tool(
    name="RAGIngest",
    func=ingest_knowledge_base,
    description=(
        "Builds or refreshes the RAG index: Pinecone over data/knowledge when RAG_VECTOR_BACKEND=pinecone, "
        "or local Chroma over MITRE .md files under RAG_DATA_PATH when RAG_VECTOR_BACKEND=chroma."
    ),
)

rag_retriever = Tool(
    name="RAGRetriever",
    func=retrieve_security_context,
    description=(
        "Retrieves threat-relevant context from the configured RAG backend (Pinecone semantic index or "
        "local Chroma MITRE index). Input: question, log snippet, or IOC text."
    ),
)
