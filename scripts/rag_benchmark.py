"""Lightweight RAG benchmark runner.

Runs a small set of deterministic queries against the local Chroma index and
reports pass/fail per case along with scores and citations.
"""

from __future__ import annotations

import sys
from typing import Dict, List

from src.tools.rag_tools import retrieve_security_context

CASES: List[Dict[str, object]] = [
    {
        "name": "credential dumping",
        "query": "credential dumping",
        "expected_sources": ["T1003_OS_Credential_Dumping.md"],
        "min_score": 0.40,
    },
    {
        "name": "sql injection prevention",
        "query": "sql injection prevention",
        "expected_sources": ["mitre_attack_quickmap.md", "owasp_top10_web_playbook.md"],
        "min_score": 0.35,
    },
    {
        "name": "ransomware response",
        "query": "ransomware response actions",
        "expected_sources": ["ransomware_response.md"],
        "min_score": 0.35,
    },
    {
        "name": "web login brute force",
        "query": "web login brute force detection",
        "expected_sources": ["network_ioc_triage.md", "authentication_abuse.md"],
        "min_score": 0.30,
    },
    {
        "name": "post incident review",
        "query": "post-incident review template",
        "expected_sources": ["post_incident_review_template.md"],
        "min_score": 0.30,
    },
]


def _matches_source(citations: List[str], expected_sources: List[str]) -> bool:
    citations_lower = [c.lower() for c in citations]
    return any(any(exp.lower() in c for c in citations_lower) for exp in expected_sources)


def run_case(case: Dict[str, object]) -> Dict[str, object]:
    query = str(case["query"])
    expected = case.get("expected_sources", []) or []
    min_score = float(case.get("min_score", 0.0))

    result = retrieve_security_context(query)
    passed = False
    reason = ""

    if result.status == "error":
        reason = f"error: {result.error_message}"
    elif result.status == "no_results":
        reason = "no results"
    else:
        max_score = max(result.scores) if result.scores else 0.0
        if not _matches_source(result.citations, expected):
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
