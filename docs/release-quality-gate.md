# Release Quality Gate

> Defines what "shippable" means for this sprint. Person 1 (Platform Lead) runs this checklist before any release tag.

## 1. Automated Gates (all must pass)

| Gate | Command | Pass Criteria | Blocks Release |
|------|---------|---------------|----------------|
| Compile check | `make lint` | Exit 0 | Yes |
| Unit + smoke tests | `make test-ci` | Exit 0, 0 failures | Yes |
| Benchmark pipeline | `make benchmark` (offline) | Exit 0, `latest.json` produced | Yes |
| Memory smoke | `pytest -q tests/unit/test_memory.py` | Exit 0 | Yes |
| Frontend tests | `npm --prefix apps/web run test -- --passWithNoTests` | Exit 0 | Yes |
| Full CI workflow | GitHub Actions on Python 3.10 + 3.11 | Green on both | Yes |

## 2. Test Health Threshold

- All tests listed as PASS in `docs/test-tracker.md` must remain passing.
- The 11 legacy-regression excluded tests must be fixed and restored to CI by end of sprint. If any remain excluded, the owning person must provide a written justification in the tracker and Person 1 must approve the exception.
- The 6 integration tests requiring `OPENAI_API_KEY` remain excluded from CI but must pass when run manually at least once before release.

## 3. Manual Checks Before Release

| Check | Who | How | Result |
|-------|-----|-----|--------|
| Integration tests pass locally | Person 2 | `OPENAI_API_KEY=xxx pytest tests/integration/test_agent_flow.py` | ☐ |
| Real-LLM benchmark (G1) | Person 1 | `BENCHMARK_MODE=real-llm make benchmark` — verify `average_f1_score >= 0.5` | ☐ |
| Real-LLM benchmark (G2) | Person 1 | `BENCHMARK_AGENT_MODE=g2 BENCHMARK_MODE=real-llm make benchmark` | ☐ |
| Policy gates functional | Person 1 | Send a prompt-injection input via `/chat`, verify `stop_reason=needs_human` | ☐ |
| Sandbox end-to-end | Person 5 | Run `/sandbox/simulate` then `/sandbox/analyze` for `sqli`, `xss`, `bruteforce` | ☐ |
| Frontend renders response | Person 1 | Start API + web, submit a query, verify trace renders in UI | ☐ |

## 4. Signoff

Release requires explicit signoff from:

1. **Person 1** (Platform Lead) — confirms all automated gates pass and manual checks completed
2. **Person 2** (ReAct Owner) — confirms agent reasoning paths are stable
3. **At least one of Person 3/4/5** — confirms their subsystem works end-to-end

Signoff is recorded as a comment on the release PR:
```
RELEASE SIGNOFF: [Person N] confirms [subsystem] is ready.
```

## 5. What Does NOT Block Release

- Benchmark metric thresholds (F1, precision, recall) below target — tracked but not blocking this sprint.
- Frontend visual polish issues.
- Documentation gaps outside of `docs/contracts.md`.
