Stage 1 Work Log
Branch: memory_update
Focus: Memory contract validation + session persistence hardening
What I did:

Added strict schema validation to ConversationMemory.load_state() — messages now require valid role and content keys, and invalid roles raise ValueError explicitly instead of silently loading bad state
Malformed episodic entries are now skipped (with a continue) rather than crashing the load, so a single corrupt episode doesn't take down the whole session restore
Replaced the direct file write in SessionManager.save_session() with an atomic write-temp-then-rename pattern using tempfile.mkstemp + os.replace — a crash mid-write no longer leaves a truncated JSON file
Added corrupt-file recovery to load_session() — if JSON parsing fails, the bad file is renamed to .corrupt.json for post-mortem and the session returns a clean empty state rather than propagating an exception
Excluded .corrupt.json files from the pruning loop in prune_expired_sessions() so backup files aren't silently deleted before someone can inspect them
Added 6 new tests: invalid role rejection, missing key rejection, malformed episodic entry skipping, atomic write round-trip, corrupt file recovery, and a deterministic multi-turn replay test

What I tested:

All existing tests still pass
All 6 new tests pass
Manually verified the .corrupt.json backup is created when a session file contains invalid JSON

What's deferred to next Stage:

Recall ranking quality — current token-overlap scoring is still in place
Summary compression readability — still using the pipe-delimited format

Stage 2 Work Log
Branch: memory_update
Focus: BM25-style recall scoring + deduplication + recency boost
What I did:

Replaced the simple Jaccard token-overlap scorer in retrieve_relevant_memories() with a lightweight BM25-inspired implementation (_bm25_score) — no external dependencies, pure Python using math and collections.Counter
Added _tokens_list() as a companion to the existing _tokens() — returns an ordered list with duplicates preserved, which BM25 needs for term frequency calculation
Added a recency boost to episodic memory scoring: later entries in episodic_memories (more recent) get up to a 20% score multiplier, so a relevant recent episode ranks above an equally relevant old one
Added deduplication in retrieve_relevant_memories() — items whose first 60 characters match are collapsed so near-identical repeated episodes don't flood the recall results
Kept _token_overlap_score in place and marked it as backwards-compatible for any callers that reference it directly
Added 4 new tests: BM25 term frequency sensitivity, relevant-item ranking order, near-duplicate deduplication, recency boost preference

What I tested:

All existing tests still pass
All 4 new tests pass
Spot-checked recall output on the existing test_long_term_memory_recall_returns_relevant_items test — relevant items still surface correctly with the new scorer

What's deferred to next Stage:

Summary compression readability — still using the old pipe-delimited format
Context size cap — render_context() still has no total character limit

Stage 3 Work Log
Branch: memory_update
Focus: Summary drift control + context size cap + ReAct prompt integration logging
What I did:

Rewrote _update_summary() to produce human-readable compressed turns instead of the raw pipe-delimited wall of text — each overflow turn is now rendered as role: first sentence... on its own line, separated by --- markers between batches
Long turns are truncated to 120 characters in the summary (first sentence only) to keep the rolling summary scannable rather than accumulating full message bodies
When the summary exceeds max_summary_chars, it now trims from the front (oldest content) and prepends ...[earlier context trimmed]... rather than silently cutting the tail
Added a MAX_CONTEXT_CHARS = 4000 class-level cap to render_context() — contexts that exceed this are trimmed from the middle with a ...[context trimmed for length]... marker so both the summary and the most recent turn are always preserved
Added a DEBUG-level log line in StatefulSecurityAgent.invoke() that reports context character count, episodic count, and semantic fact count — makes it easy to spot runaway context growth in long sessions
Added 4 new tests: summary readability check (no pipe walls), context size cap enforcement, trim marker presence when over limit, and a no-crash check for the agent context size log

What I tested:

All existing tests still pass
All 4 new tests pass
Verified that a 10-turn session with 500-character messages stays within MAX_CONTEXT_CHARS after render_context()

What's deferred to next Stage:

Formal eval harness — quality scoring is still manual spot-checks might need to make a new evaluation for Memory
Documentation and quality report

Stage 4 Work Log
Branch: memory_update
Focus: Eval harness, CI quality gate, final hardeningA
What I did:

Created src/utils/eval_memory.py — a standalone memory quality evaluator that can be run as a script (python -m src.utils.eval_memory)or via make command(make evaluate-memory) or imported in CI
Evaluator covers four dimensions: recall hit rate (fraction of topic probes that surface a relevant memory), context size compliance, summary readability, and session round-trip fidelity
MemoryEvalResult.score is a simple average across the four checks — anything below 0.75 causes the script to exit with code 1, making it easy to wire into a CI step
_make_seeded_memory() builds a deterministic multi-turn session covering ransomware, VPN brute-force, SQL injection, and CVE patching — the same scenario types the agent sees in production
Added 3 new tests: recall hit rate passes threshold on seeded memory, session round-trip passes, full eval score is above 0.75
Ran the full eval script end-to-end and confirmed exit code 0 with score ≥ 0.75
Reviewed all changes across all four stages for consistency — no regressions introduced

What I tested:

All existing tests still pass across all four stages of changes
All 3 new stage 4 tests pass
python -m src.utils.eval_memory exits 0 with current implementation
Manually verified .corrupt.json recovery, BM25 ranking, summary readability, and context size cap all behave correctly end-to-end in a single simulated session

Outcome:
Remaining gaps are embedding-based semantic similarity (would replace BM25 for higher recall precision) and cross-session memory sharing — both are candidates.

Stage 5 work log 
Branch: memory_update
What I did:

Added EmbeddingBackend class to memory_manager.py supporting two providers: OpenAI text-embedding-3-small (production) and Ollama nomic-embed-text (local dev). Provider is selected via EMBEDDING_PROVIDER env var; no code changes needed to switch
Implemented cosine similarity scoring in _retrieve_by_embedding() replacing BM25 as the primary recall path — BM25 is automatically used as fallback when embeddings are unavailable or disabled
Embeddings are stored in parallel lists _episodic_embeddings / _semantic_embeddings alongside the memory entries, kept in sync by _enforce_long_term_limits() trimming both lists together
Embeddings are intentionally excluded from get_state() and re-computed on load_state() — avoids storing potentially large float arrays in session JSON and keeps the persistence format clean
Added EMBEDDING_PROVIDER, EMBEDDING_ENABLED, OPENAI_EMBEDDING_MODEL, OLLAMA_BASE_URL, OLLAMA_EMBEDDING_MODEL to settings.py and validate()
Added numpy>=1.26.0 to requirements.txt; Ollama uses stdlib urllib so no new package needed for that path
Set EMBEDDING_ENABLED=false in CI env so all tests run against BM25 — no OpenAI credits consumed on push
Added 10 new tests covering: OpenAI mock, Ollama mock, disabled backend, graceful failure, cosine similarity edge cases, embedding recall path, BM25 fallback, and session round-trip re-embedding

What I tested:

All 16 existing tests still pass with EMBEDDING_ENABLED=false
All 10 new tests pass
Manually verified OpenAI embedding path returns a 1536-dim vector for text-embedding-3-small
Manually verified Ollama path works with nomic-embed-text pulled locally via ollama pull nomic-embed-text