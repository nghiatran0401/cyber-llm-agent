"""Optional benchmark for the local Chroma MITRE index.

Exits 0 immediately when ``RAG_VECTOR_BACKEND`` is not ``chroma`` (default is Pinecone).
When using Chroma, expects ``data/mitre`` (or ``RAG_DATA_PATH``) to contain markdown
that yields the cited filenames for each case — tune ``CASES`` for your corpus.
"""

from __future__ import annotations

import sys
from typing import Dict, List

from src.config.settings import Settings
from src.tools.rag_tools import get_rag_result

CASES: List[Dict[str, object]] = [
    {
        "name": "credential dumping",
        "query": "credential dumping",
        "expected_sources": ["T1003_OS_Credential_Dumping.md"],
        "min_score": 0.25,
    },
]


def _matches_source(citations: List[str], expected_sources: List[str]) -> bool:
    citations_lower = [c.lower() for c in citations]
    return any(any(exp.lower() in c for c in citations_lower) for exp in expected_sources)


def run_case(case: Dict[str, object]) -> Dict[str, object]:
    query = str(case["query"])
    expected = case.get("expected_sources", []) or []
    min_score = float(case.get("min_score", 0.0))

    result = get_rag_result(query)
    passed = False
    reason = ""

    if result.status == "error":
        reason = f"error: {result.error_message}"
    elif result.status == "no_results":
        reason = "no results"
    else:
        max_score = max(result.scores) if result.scores else 0.0
        if expected and not _matches_source(result.citations, list(expected)):
            reason = f"missing expected sources ({expected})"
        elif max_score < min_score:
            reason = f"score {max_score:.3f} below min {min_score:.3f}"
        else:
            passed = True
            reason = f"ok (max_score={max_score:.3f})"

    return {
        "name": case.get("name", query),
        "status": "pass" if passed else "fail",
        "reason": reason,
        "citations": result.citations,
        "scores": result.scores,
    }


def main() -> int:
    if Settings.RAG_VECTOR_BACKEND != "chroma":
        print("Skipping RAG benchmark: RAG_VECTOR_BACKEND is not chroma (default is pinecone).")
        return 0

    results = [run_case(case) for case in CASES]
    failed = [r for r in results if r["status"] == "fail"]

    for res in results:
        print(f"[{res['status'].upper()}] {res['name']}: {res['reason']}")
        if res.get("citations"):
            print(f"  citations: {res['citations']}")
        if res.get("scores"):
            print(f"  scores: {res['scores']}")

    if failed:
        print(f"\nBenchmark failed: {len(failed)} case(s) did not meet expectations.")
        return 1
    print("\nBenchmark passed: all cases met expectations.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
