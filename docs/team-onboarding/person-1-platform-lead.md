# Person 1 Onboarding - Platform Lead (Infra, Quality, CI/CD, API)

## 1) Project Context (plain English)

This project is a cybersecurity assistant with:

- backend API (FastAPI)
- agent runtime (G1 single-agent + G2 multi-agent)
- web UI (Next.js)
- sandbox/lab for simulated attacks

Your role is not to build one mechanism deeply. Your job is to make the entire system stable, testable, and shippable.

## 2) Current Status (frank)

Current maturity for your track: **6.5/10**

What this means:

- The system works for demos.
- Core features exist.
- But quality gates are not strict enough yet, and some test modules are still excluded in CI.

Main reality today:

- API logic is heavy in `services/api/main.py` and still too centralized.
- CI uses a reduced test set (`make test-ci`) and ignores some important tests.
- Shared contracts exist, but are not enforced strongly enough in day-to-day PR flow.

## 3) What Is Already Implemented

- FastAPI routes for health, readiness, analyze/chat, streaming, sandbox, metrics.
- Basic auth/rate-limit middleware hooks.
- Unified API response schemas.
- CI workflow running lint/test/benchmark/web tests.
- Makefile with standard dev commands.
- Benchmark and smoke scripts.

## 4) What Must Improve

- Break API monolith into maintainable modules.
- Make CI trustworthy (reduce ignored tests over time).
- Enforce cross-team contracts (trace/tool/memory/RAG/API envelopes).
- Improve release discipline (clear signoff criteria).
- Keep integration quality high while 4 mechanism owners work in parallel.

## 5) Your 4-Week Plan

### Week 1

- Freeze contracts and publish PR checklist.
- Track all skipped/failing tests with owners.
- Define release quality gate for this sprint.

### Week 2

- Refactor API structure into route/middleware/metrics focused files.
- Add stronger CI reporting (what failed, owner, severity).

### Week 3

- Lead integration week; unblock cross-track conflicts fast.
- Validate end-to-end API -> agent -> UI trace consistency.

### Week 4

- Stabilization + bug triage.
- Release candidate + final signoff.

## 6) First Files To Read

- `services/api/main.py`
- `services/api/schemas.py`
- `.github/workflows/ci.yml`
- `Makefile`
- `scripts/smoke_checklist.py`
- `src/benchmarking/runner.py` (run as `python -m src.benchmarking.runner`)

## 7) How You Know You Are Succeeding

- CI signal becomes trusted by the team.
- Integration failures are found early, not at demo time.
- No major contract-breaking merges.
- Team can ship weekly with confidence.
