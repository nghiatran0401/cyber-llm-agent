from typing import List

from ..data_models import RetrievedContext


def simple_rerank(contexts: List[RetrievedContext]) -> List[RetrievedContext]:
    """
    Lightweight reranker.

    Currently just sorts by ascending distance (score) and returns, but this
    module is a hook point for adding a cross-encoder or heuristic boosts
    later without changing callers.
    """
    return sorted(contexts, key=lambda c: c.score)

