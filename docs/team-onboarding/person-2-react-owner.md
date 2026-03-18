# Person 2 Onboarding - ReAct Owner

## 1) Project Context (plain English)

ReAct means the agent should:

- think about next step
- call tools when needed
- read tool output
- continue until final answer

In this project, G1 is closest to ReAct behavior. G2 is a more structured pipeline, but still needs clear reasoning trace.

## 2) Current Status (frank)

Current maturity for your track: **6.0/10**

What this means:

- Agent loops and traces exist.
- But the ReAct contract is not explicit enough yet.
- Some behavior is still string-heavy and less deterministic than it should be.

Main reality today:

- Trace quality is useful, but not fully standardized end-to-end.
- Loop control exists, but needs tighter policy and clearer stop reasons.
- Important tests for this area are currently not fully active in CI.

## 3) What Is Already Implemented

- G1 single-agent runner with bounded execution path.
- G2 runner with step trace emission.
- Workspace stream endpoint for live trace updates.
- Frontend components for trace and monitor state.
- Safety gates integrated around execution output.

## 4) What Must Improve

- Define strict ReAct step schema (`thought/action/observation/final`).
- Make loop stop reasons deterministic and auditable.
- Reduce unnecessary tool calls.
- Ensure trace fields are consistent from backend to UI.
- Re-enable and stabilize ReAct-related tests.

## 5) Your 4-Week Plan

### Week 1

- Finalize ReAct schema and trace contract.
- Add/repair tests for loop step integrity and stop reasons.

### Week 2

- Implement stronger loop controller policy (steps/tools/time budgets).
- Standardize confidence + stop reason outputs.

### Week 3

- Integrate cleanly with RAG, memory, and tooling contracts.
- Improve trace readability and consistency in UI.

### Week 4

- Hardening and edge-case fixes.
- Publish ReAct quality report (precision, over-calling, completion quality).

## 6) First Files To Read

- `src/agents/g1/adaptive_agent.py`
- `src/agents/g1/agent_with_memory.py`
- `src/agents/g2/runner.py`
- `services/api/g1_service.py`
- `services/api/g2_service.py`
- `apps/web/components/TracePanel.tsx`
- `apps/web/lib/monitor-state.ts`

## 7) How You Know You Are Succeeding

- ReAct trace is predictable and easy to explain.
- Fewer wasteful tool calls.
- Stop reasons are always meaningful.
- UI and backend agree on step semantics.
