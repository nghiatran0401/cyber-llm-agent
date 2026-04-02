# Worklog — Person 3 (RAG owner)

## Cumulative summary (weeks 4–12)

*Cumulative total = sum of hours from week 4 through that row.*

| Week # | Major work done this week | Total hours spent this week | Cumulative total |
|--------|---------------------------|-----------------------------|------------------|
| 4 | Freeze RAG retrieval/citation contract; repair `test_rag_tools` vs current `rag_tools` behavior | 10 | 10 |
| 5 | Iterate chunking + ranking on `data/knowledge` samples; document chosen parameters | 12 | 22 |
| 6 | Normalize citation strings and metadata from `get_rag_result` / ingest paths; improve empty-index messaging | 11 | 33 |
| 7 | Wire trace-friendly RAG step summaries for G1 tool calls; align with ReAct owner on step text | 10 | 43 |
| 8 | Add latency/regression checks for retrieve path; harden Pinecone-disabled / offline scenarios | 12 | 55 |
| 9 | Extend benchmark/threat-case notes for retrieval quality; fix flaky ingest test | 9 | 64 |
| 10 | Clean duplicate or noisy knowledge files; dedupe chunk sources where needed | 10 | 74 |
| 11 | Harden failure modes (missing API key, index errors); operator README for ingest + env | 11 | 85 |
| 12 | RAG milestone quality summary; request Platform sign-off on frozen contract | 8 | 93 |

---

## Role reference

| Field | Value |
|-------|--------|
| **Role** | RAG owner — retrieval quality, citations, knowledge integration |
| **Track maturity (onboarding)** | 4.5 / 10 → **target 8.0** in 4 weeks |
| **CI test owner (typical)** | `test_rag_tools` |

### Mission (plain English)

Ground answers in **project knowledge**: **relevant** chunks, **clear citations**, graceful **no-result** behavior, and a **stable contract** for G1/G2 and tools.

### Key files

- `src/tools/rag_tools.py`, `tests/unit/test_rag_tools.py`, `data/knowledge/`  
- `services/api/g1_service.py`, `src/agents/g2/nodes.py` (as applicable)  

### References

- `data/docs/team-onboarding/person-3-rag-owner.md`  
- `docs/tool-contracts.md`  

---

## Dated log (optional)

_Add `### YYYY-MM-DD` bullets below for extra notes._
