# Worklog — Person 4 (Memory owner)

## Cumulative summary (weeks 4–12)

*Cumulative total = sum of hours from week 4 through that row.*

| Week # | Major work done this week | Total hours spent this week | Cumulative total |
|--------|---------------------------|-----------------------------|------------------|
| 4 | Document memory state contract; add deterministic multi-turn `load_state` / replay tests | 8 | 8 |
| 5 | Tune embedding vs BM25 recall; validate session JSON shape after `save_session` | 10 | 18 |
| 6 | Harden persistence (atomic write, corrupt `.corrupt.json` path); expand session prune tests | 9 | 27 |
| 7 | Integrate with G1 `render_context` caps; tune episodic/semantic limits vs `max_context_chars` | 11 | 38 |
| 8 | Refresh `eval_memory` harness; ensure CI-safe paths with `EMBEDDING_ENABLED=false` | 10 | 48 |
| 9 | Review recall relevance on real transcripts; adjust episodic summary length if needed | 8 | 56 |
| 10 | Cross-check API `session_id` normalization (`g1_service`) with `SessionManager` filename rules | 12 | 68 |
| 11 | Document `EMBEDDING_ENABLED`, BM25 fallback, and ops implications in README / internal wiki | 9 | 77 |
| 12 | Memory quality mini-report; validate two-turn demo (codename recall) against Docker API | 10 | 87 |

---

## Role reference

| Field | Value |
|-------|--------|
| **Role** | Memory owner — conversational state, long-term recall, session persistence |
| **Track maturity (onboarding)** | 6.5 / 10 → **target 8.2** in 4 weeks |
| **CI test owner (typical)** | `test_memory` (+ `test_embedding_memory` as applicable) |

### Mission (plain English)

**Short-term** buffer/summary, **long-term** episodic + semantic stores, **relevance-ranked recall** (embeddings + BM25 fallback), **durable session** files.

### Key files

- `src/utils/memory_manager.py`, `src/utils/session_manager.py`, `src/utils/embedding.py`  
- `src/agents/g1/g1_agent.py`, `services/api/g1_service.py`  
- `tests/unit/test_memory.py`, `tests/unit/test_embedding_memory.py`, `src/utils/eval_memory.py`  

### References

- `data/docs/team-onboarding/person-4-memory-owner.md`  

---

## Dated log (optional)

_Add `### YYYY-MM-DD` bullets below for extra notes._
