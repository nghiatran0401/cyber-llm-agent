from typing import List, Optional, Dict, Any

from .vector_store import get_mitre_collection
from ..config import get_settings
from ..data_models import RetrievedContext


def retrieve_mitre_contexts(
    query: str,
    technique_id: Optional[str] = None,
    extra_filters: Optional[Dict[str, Any]] = None,
) -> List[RetrievedContext]:
    """
    Query the MITRE Chroma collection and return retrieved contexts.

    Optional filters (e.g., technique_id) are mapped into Chroma `where`
    clauses so that we can narrow results when the query rewriter infers
    specific techniques.
    """
    settings = get_settings()
    collection = get_mitre_collection()

    where: Dict[str, Any] = {}
    if technique_id:
        where["technique_id"] = technique_id
    if extra_filters:
        where.update(extra_filters)

    results = collection.query(
        query_texts=[query],
        n_results=settings.top_k,
        where=where or None,
    )

    documents = results.get("documents", [[]])[0]
    metadatas = results.get("metadatas", [[]])[0]
    distances = results.get("distances", [[]])[0]

    contexts: List[RetrievedContext] = []
    for doc, meta, dist in zip(documents, metadatas, distances):
        contexts.append(
            RetrievedContext(
                document=doc,
                metadata=meta,
                score=float(dist),
            )
        )
    return contexts

