"""Basic local RAG helpers for security knowledge retrieval."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

from langchain_core.tools import Tool

from src.config.settings import Settings
from src.utils.logger import setup_logger

logger = setup_logger(__name__)

_TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9_.:-]{2,}")
_RAG_INDEX_PATH = Settings.KNOWLEDGE_DIR / "rag_index.json"
_ALLOWED_SUFFIXES = {".txt", ".md", ".log", ".json", ".jsonl"}


@dataclass
class _Chunk:
    source: str
    chunk_id: int
    text: str


def _tokenize(text: str) -> set[str]:
    return {token.lower() for token in _TOKEN_PATTERN.findall(text or "")}


def _chunk_text(text: str, chunk_size: int) -> List[str]:
    words = (text or "").split()
    if not words:
        return []
    chunks: List[str] = []
    for idx in range(0, len(words), chunk_size):
        chunks.append(" ".join(words[idx : idx + chunk_size]).strip())
    return [chunk for chunk in chunks if chunk]


def ingest_knowledge_base() -> str:
    """Index files under knowledge directory into a lightweight chunk store."""
    sources = [
        path
        for path in Settings.KNOWLEDGE_DIR.rglob("*")
        if path.is_file() and path.suffix.lower() in _ALLOWED_SUFFIXES
    ]
    chunks: List[dict[str, str | int]] = []
    for source in sources:
        try:
            content = source.read_text(encoding="utf-8")
        except Exception:
            logger.warning("Skipping unreadable knowledge source: %s", source)
            continue
        rel_source = str(source.relative_to(Settings.BASE_DIR))
        for idx, chunk in enumerate(_chunk_text(content, Settings.RAG_CHUNK_SIZE), start=1):
            chunks.append({"source": rel_source, "chunk_id": idx, "text": chunk})
    _RAG_INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    _RAG_INDEX_PATH.write_text(json.dumps(chunks, ensure_ascii=True, indent=2), encoding="utf-8")
    logger.info("RAG index refreshed with %s chunks from %s sources.", len(chunks), len(sources))
    return f"RAG index refreshed. sources={len(sources)} chunks={len(chunks)}"


def _load_chunks() -> List[_Chunk]:
    if not _RAG_INDEX_PATH.exists():
        ingest_knowledge_base()
    try:
        raw = json.loads(_RAG_INDEX_PATH.read_text(encoding="utf-8"))
    except Exception:
        logger.warning("RAG index is invalid. Rebuilding.")
        ingest_knowledge_base()
        raw = json.loads(_RAG_INDEX_PATH.read_text(encoding="utf-8"))
    chunks: List[_Chunk] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        source = str(item.get("source", "unknown"))
        chunk_id = int(item.get("chunk_id", 0))
        text = str(item.get("text", "")).strip()
        if not text:
            continue
        chunks.append(_Chunk(source=source, chunk_id=chunk_id, text=text))
    return chunks


def retrieve_security_context(query: str) -> str:
    """Retrieve top local knowledge snippets with explicit citations."""
    clean_query = (query or "").strip()
    if not clean_query:
        return "No retrieval performed because query is empty."
    chunks = _load_chunks()
    if not chunks:
        return (
            "No local knowledge indexed yet.\n"
            f"Add files under {Settings.KNOWLEDGE_DIR} and run RAGIngest."
        )

    query_tokens = _tokenize(clean_query)
    if not query_tokens:
        return "No retrieval performed because query does not contain searchable tokens."

    scored: List[tuple[float, _Chunk]] = []
    for chunk in chunks:
        chunk_tokens = _tokenize(chunk.text)
        if not chunk_tokens:
            continue
        overlap = len(query_tokens.intersection(chunk_tokens))
        if overlap == 0:
            continue
        score = overlap / max(len(query_tokens), 1)
        scored.append((score, chunk))

    if not scored:
        return "No relevant context found in local knowledge base."

    scored.sort(key=lambda item: item[0], reverse=True)
    top = scored[: Settings.RAG_MAX_RESULTS]
    lines = ["Retrieved Context:"]
    for score, chunk in top:
        lines.append(
            f"- score={score:.2f} source={chunk.source}#chunk-{chunk.chunk_id}: {chunk.text}"
        )
    lines.append("Citations:")
    for _, chunk in top:
        lines.append(f"- {chunk.source}#chunk-{chunk.chunk_id}")
    return "\n".join(lines)


rag_ingest = Tool(
    name="RAGIngest",
    func=ingest_knowledge_base,
    description=(
        "Indexes local knowledge files under data/knowledge for retrieval. "
        "Call this after adding or updating docs."
    ),
)

rag_retriever = Tool(
    name="RAGRetriever",
    func=retrieve_security_context,
    description=(
        "Retrieves relevant context from local knowledge files. "
        "Input should be a threat question, log snippet, or IOC statement."
    ),
)

