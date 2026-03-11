# Person 2 Onboarding - ReAct Owner (Clarified Tasks)

## 1) Role Mission

Own the ReAct behavior end-to-end so agent execution is deterministic, auditable, and efficient.

ReAct loop in this project:

1. `thought` (what to do next)
2. `action` (tool call or direct answer step)
3. `observation` (tool result handling)
4. `final` (stop with clear reason)

## 2) In-Scope vs Out-of-Scope

In-scope:

- ReAct schema and loop controller rules in G1 and G2 runtimes.
- Trace contract from backend emission to frontend display.
- Stop-reason policy and confidence output format.
- ReAct-related tests, CI stability, and quality metrics.

Out-of-scope:

- New infrastructure stack design (Person 1).
- Retrieval ranking design (Person 3).
- Memory model design (Person 4).
- New tool business logic (Person 5).

## 3) Current Status

Current maturity: **6.0/10**

Known gaps:

- Step schema is not strict enough across all paths.
- Stop reasons can be inconsistent between runs.
- Some tool calls are unnecessary.
- ReAct tests are not consistently active in CI.

## 4) Priority Backlog (Clear Work Items)

## P0 (must finish first)

- Define single ReAct step schema used by all runners.
  - Deliverable: shared schema + validation in runtime path.
  - Acceptance: no step emitted without required fields (`type`, `content`, `ts`, `step_id`).
- Enforce deterministic stop reasons.
  - Deliverable: normalized stop reason enum.
  - Acceptance: every completed run has exactly one valid stop reason.
- Re-enable core ReAct tests in CI.
  - Deliverable: passing tests for loop integrity and stop-policy behavior.
  - Acceptance: CI gate fails on schema or stop-reason regressions.

## P1 (finish after P0)

- Add loop budget policy (max steps, max tool calls, timeout budget).
  - Deliverable: centralized loop guard config.
  - Acceptance: run terminates predictably when limits are reached.
- Reduce wasteful tool calls.
  - Deliverable: simple pre-call checks and dedupe policy.
  - Acceptance: measurable drop in redundant calls on benchmark set.
- Align backend trace payload and frontend rendering.
  - Deliverable: contract table and field mapping.
  - Acceptance: trace panel shows all required fields without fallback parsing.

## P2 (hardening/reporting)

- Edge-case handling (tool failure, empty observation, malformed result).
  - Deliverable: retry/abort rules documented and tested.
  - Acceptance: no silent failure path in loop execution.
- Publish ReAct quality report.
  - Deliverable: weekly metrics (`completion_rate`, `avg_steps`, `tool_call_precision`, `stop_reason_distribution`).
  - Acceptance: report is reproducible from benchmark script.

## 5) 4-Week Execution Plan

Week 1:

- Lock schema + stop-reason enum.
- Repair/add CI tests for step integrity.

Week 2:

- Implement budget controller (steps/tools/time).
- Add deterministic termination behavior.

Week 3:

- Contract alignment with RAG, memory, tooling owners.
- Frontend trace consistency fixes.

Week 4:

- Hardening for failure cases.
- Final quality report and handoff notes.

## 6) Handoff Dependencies

You need from Person 3/4/5:

- stable response envelopes for retrieval/memory/tool outputs
- error-code conventions for failed actions

You provide to Person 1:

- CI test list and pass criteria for ReAct gates
- schema version and migration notes

## 7) First Files To Read

- `src/agents/g1/adaptive_agent.py`
- `src/agents/g1/agent_with_memory.py`
- `src/agents/g2/runner.py`
- `services/api/g1_service.py`
- `services/api/g2_service.py`
- `apps/web/components/TracePanel.tsx`
- `apps/web/lib/monitor-state.ts`

## 8) Definition of Done (for Person 2)

- ReAct schema is validated in all main execution paths.
- Stop reasons are deterministic and queryable.
- ReAct test suite is active and stable in CI.
- Trace shown in UI matches backend payload contract.
- Benchmarks show reduced redundant tool usage.
