"""RAG helpers: Pinecone + OpenAI embeddings over data/knowledge."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Literal, Optional

from langchain_core.tools import Tool
from langchain_community.document_loaders import DirectoryLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_pinecone import PineconeVectorStore
from pinecone import Pinecone, ServerlessSpec

from src.config.settings import Settings
from src.utils.embedding import create_openai_embeddings
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


def _get_pinecone_client() -> Pinecone:
    if not Settings.PINECONE_API_KEY:
        raise ValueError("PINECONE_API_KEY is not set.")
    return Pinecone(api_key=Settings.PINECONE_API_KEY)


def ingest_knowledge_base() -> str:
    """Build or refresh the Pinecone index from ``data/knowledge``."""
    if not Settings.ENABLE_RAG:
        return "RAG is disabled."

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
    embeddings = create_openai_embeddings()

    PineconeVectorStore.from_documents(chunks, embeddings, index_name=index_name)

    msg = f"RAG index refreshed using Pinecone. Processed {len(docs)} documents into {len(chunks)} chunks."
    logger.info(msg)
    return msg


def _build_chunks_from_pinecone_docs(docs) -> List[RAGChunk]:
    chunks: List[RAGChunk] = []
    knowledge_dir = Path(Settings.KNOWLEDGE_DIR)
    base_dir = Path(Settings.BASE_DIR)

    def _normalize_source_file(raw_source: object) -> Optional[str]:
        source = str(raw_source or "").strip()
        if not source:
            return None
        source_path = Path(source)

        # Prefer exact existing file under data/knowledge.
        if source_path.is_file():
            try:
                relative_to_knowledge = source_path.relative_to(knowledge_dir)
                return str(Path("data/knowledge") / relative_to_knowledge)
            except ValueError:
                try:
                    return str(source_path.relative_to(base_dir))
                except ValueError:
                    return str(source_path)

        # Fallback: try basename lookup within knowledge dir (for stale absolute paths).
        candidate = knowledge_dir / source_path.name
        if candidate.is_file():
            return str(Path("data/knowledge") / source_path.name)
        return None

    for idx, doc in enumerate(docs, start=1):
        source = _normalize_source_file(doc.metadata.get("source"))
        if source is None:
            continue
        chunks.append(
            RAGChunk(
                text=doc.page_content,
                source_file=str(source),
                chunk_id=f"chunk-{idx}",
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
    """Structured Pinecone retrieval."""
    start = time.perf_counter()
    clean_query = (query or "").strip()
    if not clean_query:
        return _make_result(query=clean_query, status="no_results", error_message="Empty query.")
    if not Settings.ENABLE_RAG:
        return _make_result(query=clean_query, status="error", error_message="RAG is disabled.")

    try:
        embeddings = create_openai_embeddings()
        vectorstore = PineconeVectorStore(
            index_name=Settings.PINECONE_INDEX_NAME,
            embedding=embeddings,
        )
        retriever = vectorstore.as_retriever(search_kwargs={"k": Settings.RAG_MAX_RESULTS})
        docs = retriever.invoke(clean_query)
        latency_ms = (time.perf_counter() - start) * 1000
        if not docs:
            return _make_result(query=clean_query, status="no_results", latency_ms=latency_ms)
        rag_chunks = _build_chunks_from_pinecone_docs(docs)
        if not rag_chunks:
            return _make_result(
                query=clean_query,
                status="no_results",
                error_message="No valid knowledge-file citations in retrieval results.",
                latency_ms=latency_ms,
            )
        return _make_result(query=clean_query, status="ok", chunks=rag_chunks, latency_ms=latency_ms)
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
    """Retrieves threat-relevant context from the Pinecone knowledge index."""
    result = get_rag_result(query)
    return format_rag_result(result, source_label="pinecone_semantic")


rag_ingest = Tool(
    name="RAGIngest",
    func=ingest_knowledge_base,
    description=(
        "Builds or refreshes the Pinecone semantic index from documents under data/knowledge "
        "(.md, .txt, .log, .json, .jsonl)."
    ),
)

rag_retriever = Tool(
    name="RAGRetriever",
    func=retrieve_security_context,
    description=(
        "Retrieves threat-relevant context from the Pinecone knowledge index. "
        "Input: question, log snippet, or IOC text."
    ),
)
