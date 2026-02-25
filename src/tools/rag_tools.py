"""Local RAG helpers with semantic retrieval and reranking."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

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
    vector: List[float]


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


def _embed_text(text: str, dims: int) -> List[float]:
    """Create deterministic local embeddings using hashed token projection."""
    vector = [0.0] * dims
    tokens = _tokenize(text)
    if not tokens:
        return vector
    for token in tokens:
        token_hash = hash(token)
        idx = token_hash % dims
        sign = 1.0 if (token_hash & 1) == 0 else -1.0
        vector[idx] += sign
    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0:
        return vector
    return [value / norm for value in vector]


def _cosine_similarity(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    return float(sum(left * right for left, right in zip(a, b)))


def ingest_knowledge_base() -> str:
    """Index files under knowledge directory into chunked semantic index."""
    sources = [
        path
        for path in Settings.KNOWLEDGE_DIR.rglob("*")
        if path.is_file()
        and path.suffix.lower() in _ALLOWED_SUFFIXES
        and path.resolve() != _RAG_INDEX_PATH.resolve()
    ]
    chunks: List[dict[str, object]] = []
    for source in sources:
        try:
            content = source.read_text(encoding="utf-8")
        except Exception:
            logger.warning("Skipping unreadable knowledge source: %s", source)
            continue
        rel_source = str(source.relative_to(Settings.BASE_DIR))
        for idx, chunk in enumerate(_chunk_text(content, Settings.RAG_CHUNK_SIZE), start=1):
            chunks.append(
                {
                    "source": rel_source,
                    "chunk_id": idx,
                    "text": chunk,
                    "vector": _embed_text(chunk, Settings.RAG_EMBEDDING_DIMS),
                }
            )
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
        vector = item.get("vector")
        if not isinstance(vector, list) or len(vector) != Settings.RAG_EMBEDDING_DIMS:
            vector = _embed_text(text, Settings.RAG_EMBEDDING_DIMS)
        chunks.append(
            _Chunk(
                source=source,
                chunk_id=chunk_id,
                text=text,
                vector=[float(value) for value in vector],
            )
        )
    return chunks


def _semantic_score(query_vector: List[float], chunk: _Chunk) -> float:
    return _cosine_similarity(query_vector, chunk.vector)


def _lexical_score(query_tokens: set[str], chunk: _Chunk) -> float:
    chunk_tokens = _tokenize(chunk.text)
    if not chunk_tokens:
        return 0.0
    overlap = len(query_tokens.intersection(chunk_tokens))
    return overlap / max(len(query_tokens), 1)


def _hybrid_rerank(
    query: str,
    chunks: List[_Chunk],
) -> List[tuple[float, float, float, _Chunk]]:
    query_tokens = _tokenize(query)
    query_vector = _embed_text(query, Settings.RAG_EMBEDDING_DIMS)

    mode = Settings.RAG_RETRIEVAL_MODE
    semantic_ranked = sorted(
        [(_semantic_score(query_vector, chunk), chunk) for chunk in chunks],
        key=lambda item: item[0],
        reverse=True,
    )
    lexical_ranked = sorted(
        [(_lexical_score(query_tokens, chunk), chunk) for chunk in chunks],
        key=lambda item: item[0],
        reverse=True,
    )

    candidates: List[_Chunk] = []
    if mode in {"semantic", "hybrid"}:
        candidates.extend(chunk for _, chunk in semantic_ranked[: Settings.RAG_SEMANTIC_CANDIDATES])
    if mode in {"lexical", "hybrid"}:
        candidates.extend(chunk for _, chunk in lexical_ranked[: Settings.RAG_SEMANTIC_CANDIDATES])
    if not candidates:
        candidates = [chunk for _, chunk in semantic_ranked[: Settings.RAG_SEMANTIC_CANDIDATES]]

    deduped: Dict[str, _Chunk] = {}
    for chunk in candidates:
        key = f"{chunk.source}#chunk-{chunk.chunk_id}"
        deduped[key] = chunk

    reranked: List[tuple[float, float, float, _Chunk]] = []
    for chunk in deduped.values():
        semantic = _semantic_score(query_vector, chunk)
        lexical = _lexical_score(query_tokens, chunk)
        if mode == "semantic":
            final_score = semantic
        elif mode == "lexical":
            final_score = lexical
        else:
            final_score = (0.65 * semantic) + (0.35 * lexical)
        reranked.append((final_score, semantic, lexical, chunk))

    reranked.sort(key=lambda item: item[0], reverse=True)
    return reranked


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

    if not _tokenize(clean_query):
        return "No retrieval performed because query does not contain searchable tokens."

    reranked = _hybrid_rerank(clean_query, chunks)
    top = reranked[: Settings.RAG_MAX_RESULTS]
    top = [entry for entry in top if entry[0] > 0]
    if not top:
        return "No relevant context found in local knowledge base."

    lines = [f"Retrieved Context (mode={Settings.RAG_RETRIEVAL_MODE}):"]
    for final_score, semantic_score, lexical_score, chunk in top:
        lines.append(
            "- final_score={:.3f} semantic_score={:.3f} lexical_score={:.3f} source={}#chunk-{}: {}".format(
                final_score,
                semantic_score,
                lexical_score,
                chunk.source,
                chunk.chunk_id,
                chunk.text,
            )
        )
    lines.append("Citations:")
    for _, _, _, chunk in top:
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

