# Tooling Reliability Report

> Sprint 1 final assessment.

## Current State Summary

| Dimension | LogParser | CTIFetch | OWASPSandbox |
|-----------|-----------|----------|--------------|
| Output format | ToolResult JSON envelope | ToolResult JSON envelope | Plain dict (not a LangChain tool) |
| Error handling | 5 typed error categories | 3 error types + fallback | ValueError + OSError with logging |
| Retry logic | None (local I/O) | Up to 2 retries with backoff (see `src/tools/cti_tool.py`) | N/A |
| Timeout handling | None (local I/O) | 10s per request (see `src/tools/cti_tool.py`) | N/A |
| Input validation | Path traversal + extension check | IOC format regex + empty check | Scenario key validation |
| Output sanitization | None needed (structured JSON) | Control char stripping + truncation | None needed |
| Test count | 11 tests (7 happy + 4 unhappy) | 10 tests (6 happy + 4 unhappy) | 7 tests (4 happy + 3 unhappy) |
| Telemetry | Structured logging with duration, entries | Structured logging with retries, duration | Error logging on I/O failure |
| Maturity | 8/10 | 8/10 | 7/10 |

## Changes Made

### Week 1
- Created `docs/tool-contracts.md` — standardized ToolResult envelope definition
- Added 9 new unhappy-path tests for tools, 3 new tests for sandbox
- Defined telemetry fields for all tools

### Week 2
- Created `src/tools/_tool_envelope.py` — shared `build_tool_result()` helper
- Refactored `log_parser_tool.py` — all return paths use ToolResult envelope with timing, error types, and structured logging
- Refactored `cti_tool.py` — all return paths use ToolResult envelope, retry count tracked and returned in `meta.retries`
- Added `UnicodeDecodeError` handler to log parser (was missing)
- Added `OSError` handling to `append_event_to_live_log()` in sandbox
- Updated `src/agents/g2/nodes.py` — `log_analyzer_node` and `threat_predictor_node` parse ToolResult JSON envelopes

### Week 3
- Added lab compatibility tests — verify sandbox events pass `SandboxAnalyzeRequest` validation
- Added oversized event rejection test
- Documented scenario ID mismatch between vuln-lab and sandbox as accepted divergence

### Week 4
- Added reliability tests: retry exhaustion, concurrent writes, encoding errors
- Created `docs/tooling-runbook.md` — operational debugging guide
- Created this reliability report

## Known Gaps

1. **No circuit breaker for CTI** — repeated failures still attempt OTX on every request. A circuit breaker that skips CTI for N seconds after M failures would reduce latency during outages.
2. **No CTI response cache** — identical queries within seconds hit OTX redundantly. An in-memory TTL cache would reduce rate-limiting risk.
3. **Vuln-lab scenario ID mismatch** — vuln-lab uses `sqliLogin` while sandbox uses `owasp_sqli_001`. This is documented but not resolved.
4. **No end-to-end integration test** — no test runs a full G1 agent loop with mocked tools returning error envelopes to verify the agent handles failures gracefully.
5. **Sandbox concurrent writes** — `append_event_to_live_log()` has no file locking. Concurrent writes work in practice (atomic line-level writes on most OSes) but are not guaranteed on all filesystems.

## Recommendations for Next Sprint

1. Add circuit breaker to CTI tool (skip after 3 consecutive failures for 30 seconds)
2. Add in-memory TTL cache for CTI queries (60-second TTL)
3. Unify scenario IDs across vuln-lab and OWASP sandbox
4. Add end-to-end agent loop test with tool envelope error handling
5. Add file locking to sandbox JSONL writes
