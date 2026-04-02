# Person 4 Onboarding - Memory Owner

## 1) Project Context (plain English)

Memory makes agent conversations stateful.

In this project, memory should:

- keep useful recent context
- store long-term facts/episodes
- retrieve relevant memory for new user input
- persist session state safely

## 2) Current Status (frank)

Current maturity for your track: **6.5/10**

What this means:

- Memory architecture is already decent.
- Core behavior works and is testable.
- But recall ranking and persistence robustness still need improvement.

Main reality today:

- Current recall logic is relatively simple.
- Session persistence works but needs hardening for edge cases.
- This area is close to strong, but not yet highly reliable.

## 3) What Is Already Implemented

- Conversation memory structure (buffer/summary style behavior).
- Episodic and semantic memory storage.
- Relevance-based memory retrieval.
- Session save/load and retention pruning utilities.
- Existing unit tests for memory behavior.

## 4) What Must Improve

- Improve recall relevance quality.
- Strengthen session persistence and pruning safety.
- Reduce memory drift across multi-turn conversations.
- Add better evaluation for memory usefulness.

## 5) Your 4-Week Plan

### Week 1

- Freeze memory contract (state fields and retention behavior).
- Add deterministic replay tests for multi-turn flows.

### Week 2

- Improve ranking/relevance logic.
- Harden persistence/pruning edge cases.

### Week 3

- Validate integration with ReAct loop and agent prompts.
- Tune memory limits for quality vs context size.

### Week 4

- Final hardening pass.
- Publish memory quality report and docs.

## 6) First Files To Read

- `src/utils/memory_manager.py`
- `src/utils/session_manager.py`
- `src/agents/g1/g1_agent.py`
- `tests/unit/test_memory.py`
- `services/api/g1_service.py` (session usage context)

## 7) How You Know You Are Succeeding

- Memory retrieval improves answer continuity and relevance.
- Session data remains stable and consistent.
- Memory tests catch regressions early.
- Other owners can depend on memory behavior predictably.
