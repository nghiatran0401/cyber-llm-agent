import json
import os
from datetime import datetime, timezone

from src.rag.ingestion.mitre_loader import load_mitre_documents
from src.rag.ingestion.chunking import split_mitre_documents
from src.rag.retrieval.vector_store import get_mitre_collection
from src.rag.config import get_settings


def build_mitre_index() -> None:
    """
    Build or refresh the MITRE Chroma index.

    This is the library-level function used by `scripts.build_index`.
    """
    settings = get_settings()

    print(f"Loading MITRE markdown from: {settings.data_path}")
    docs = load_mitre_documents()
    print(f"Loaded {len(docs)} documents.")

    chunks = split_mitre_documents(docs)
    print(f"Split into {len(chunks)} chunks.")

    documents = [c.page_content for c in chunks]
    metadatas = [c.metadata for c in chunks]
    ids = []
    for i, meta in enumerate(metadatas):
        chunk_id = f"ID{i}"
        meta["chunk_id"] = chunk_id
        ids.append(chunk_id)

    collection = get_mitre_collection()
    collection.upsert(documents=documents, metadatas=metadatas, ids=ids)
    print("Index build completed.")

    # Write ingestion manifest for traceability.
    manifest = {
        "source_dir": settings.data_path,
        "total_documents": len(docs),
        "total_chunks": len(chunks),
        "embedding_model": settings.embedding_model,
        "collection": settings.chroma_collection,
        "built_at": datetime.now(timezone.utc).isoformat(),
    }

    os.makedirs(settings.chroma_path, exist_ok=True)
    manifest_path = os.path.join(settings.chroma_path, "ingestion_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"Wrote ingestion manifest to {manifest_path}")

