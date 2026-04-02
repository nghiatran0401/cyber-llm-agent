# RAG Benchmark Evaluation

Lightweight, deterministic cases to spot regressions in retrieval quality and citation wiring. Each case specifies the query, the expected source file(s) that should be cited, and a minimum acceptable similarity score.

| # | Query | Expected source file(s) | Min score |
| - | ----- | ----------------------- | --------- |
| 1 | "credential dumping" | T1003_OS_Credential_Dumping.md | 0.40 |
| 2 | "sql injection prevention" | mitre_attack_quickmap.md, owasp_top10_web_playbook.md | 0.35 |
| 3 | "ransomware response actions" | ransomware_response.md | 0.35 |
| 4 | "web login brute force detection" | network_ioc_triage.md, authentication_abuse.md | 0.30 |
| 5 | "post-incident review template" | post_incident_review_template.md | 0.30 |

## How to run

```
python scripts/rag_benchmark.py
```

Outputs per-case pass/fail, score details, and a summary exit code (non-zero on failure).
