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