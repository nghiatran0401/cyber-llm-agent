# Person 3 Onboarding - RAG Owner

## 1) Project Context (plain English)

RAG helps the agent answer using project knowledge files, not only model memory.

In this project, RAG should:

- retrieve relevant security context
- return clear citations
- avoid noisy or irrelevant chunks

## 2) Current Status (frank)

Current maturity for your track: **4.5/10**

What this means:

- RAG exists, but this is the weakest area right now.
- There has been drift between implementation and tests.
- Retrieval quality and contract consistency still need serious work.

Main reality today:

- Code works in parts, but confidence is low.
- Test alignment and benchmark evidence are not strong enough yet.
- RAG contract needs to be explicit for other owners to integrate safely.

## 3) What Is Already Implemented

- RAG ingestion/retrieval tooling exists.
- Retrieval can be invoked by agent flows.
- Knowledge files are available under `data/knowledge/`.
- Basic test coverage exists for RAG behavior.

## 4) What Must Improve

- Freeze one clear retrieval output contract.
- Align tests with current implementation behavior.
- Improve relevance and citation quality.
- Handle no-result/failure cases gracefully.
- Add measurable retrieval metrics (quality + latency).

## 5) Your 4-Week Plan

### Week 1

- Define RAG contract and acceptance criteria.
- Repair tests to match intended behavior.

### Week 2

- Improve chunking and ranking.
- Normalize citation and retrieval metadata format.

### Week 3

- Integrate with ReAct/tool interfaces cleanly.
- Add benchmark cases focused on retrieval quality.

### Week 4

- Reliability + performance hardening.
- Publish final RAG quality report.

## 6) First Files To Read

- `src/tools/rag_tools.py`
- `tests/unit/test_rag_tools.py`
- `data/knowledge/`
- `docs/benchmark-evaluation.md`
- `services/api/g1_service.py` (RAG usage context)
- `src/agents/g2/nodes.py` (RAG usage context)

## 7) How You Know You Are Succeeding

- Retrieved context is relevant and cited clearly.
- RAG test suite is stable.
- Fewer “no relevant context” failures in normal scenarios.
- Other owners can rely on your output format without guesswork.
