from typing import Dict, List

from ..config import get_settings
from ..data_models import MITRETechniqueResponse, RetrievedContext
from ..logging_config import setup_logging
from ..retrieval.retriever import retrieve_mitre_contexts
from ..retrieval.reranker import simple_rerank
from ..llm.mitre_answerer import answer_mitre_query
from .query_rewriter import rewrite_query


logger = setup_logging()


def run_mitre_agent(user_query: str) -> Dict[str, object]:
    """
    High-level entrypoint for MITRE RAG.

    Pipeline:
    - Rewrite query to normalized form and infer candidate technique IDs.
    - Retrieve contexts (optionally filtered by inferred technique).
    - Rerank and answer using the LLM.
    """
    settings = get_settings()

    rewritten = rewrite_query(user_query)
    retrieval_query = rewritten.normalized_question or user_query
    inferred_technique = rewritten.technique_ids[0] if rewritten.technique_ids else None

    contexts: List[RetrievedContext] = retrieve_mitre_contexts(
        retrieval_query,
        technique_id=inferred_technique,
    )

    if not contexts:
        return {"error": "No relevant MITRE information found."}

    contexts = simple_rerank(contexts)

    best_distance = contexts[0].score
    if best_distance > settings.distance_threshold:
        return {"error": "Query out of MITRE scope."}

    mitre_resp: MITRETechniqueResponse = answer_mitre_query(retrieval_query, contexts)

    if mitre_resp.error:
        logger.warning("MITRE agent error: %s", mitre_resp.error)

    result: Dict[str, object] = {
        "technique_id": mitre_resp.technique_id,
        "technique_name": mitre_resp.technique_name,
        "tactic": mitre_resp.tactic,
        "description": mitre_resp.description,
        "detection": mitre_resp.detection,
        "mitigations": mitre_resp.mitigations,
    }
    if mitre_resp.error:
        result["error"] = mitre_resp.error

    # Attach debug info from the rewriter for transparency.
    result["rewriter"] = {
        "normalized_question": rewritten.normalized_question,
        "sub_questions": rewritten.sub_questions,
        "key_phrases": rewritten.key_phrases,
        "technique_ids": rewritten.technique_ids,
    }
    return result

