# Worklog — Person 2 (ReAct owner)

## Cumulative summary (weeks 4–12)

*Cumulative total = sum of hours from week 4 through that row.*

| Week # | Major work done this week | Total hours spent this week | Cumulative total |
|--------|---------------------------|-----------------------------|------------------|
| 4 | Audit stop reasons end-to-end; align trace fields with `docs/trace-contract.md`; add missing step tests | 9 | 9 |
| 5 | Tune loop budgets (`MAX_AGENT_STEPS`, tool-call limits); strengthen duplicate tool-call handling + tests | 11 | 20 |
| 6 | Fix `TracePanel` / `monitor-state` edge cases; harden workspace SSE stream error handling | 10 | 30 |
| 7 | **G1/G2 trace parity sprint** with Platform; normalize `StepTrace` payloads for UI consumption | 12 | 42 |
| 8 | Experiment to reduce unnecessary tool invocations; add structured logging around step transitions | 8 | 50 |
| 9 | Draft ReAct quality metrics (over-calling, completion rate); analyze sample run traces | 11 | 61 |
| 10 | UI polish: trace readability, expand/collapse, step ordering; light accessibility pass | 10 | 71 |
| 11 | Edge cases: `budget_exhausted`, `needs_human`, critic paths reflected consistently in traces | 9 | 80 |
| 12 | Publish ReAct milestone summary; walk through demo script with stakeholder; backlog for next cycle | 10 | 90 |

---

## Role reference

| Field | Value |
|-------|--------|
| **Role** | ReAct owner — reasoning loop, trace behavior, stop policy, UI alignment |
| **Track maturity (onboarding)** | 6.0 / 10 → **target 8.0** in 4 weeks |
| **CI test owner (typical)** | `test_multiagent`, `test_state_validator`, `test_prompt_manager`; shared `test_agent_flow` |

### Mission (plain English)

Ensure the agent **thinks → acts (tools) → observes → finishes** in a way that is **bounded, explainable, and visible**: consistent **step traces**, meaningful **stop reasons**, and alignment between **backend and Next.js** trace/monitor UI.

### Key files

- `src/agents/g1/g1_agent.py`, `src/agents/g2/*`  
- `services/api/g1_service.py`, `services/api/g2_service.py`, `services/api/react_runtime.py`  
- `apps/web/components/TracePanel.tsx`, `LiveMonitorPanel.tsx`, `apps/web/lib/monitor-state.ts`  
- `docs/trace-contract.md`, `docs/react-integration-contract.md`  

### References

- `data/docs/team-onboarding/person-2-react-owner.md`  

---

## Dated log (optional)

_Add `### YYYY-MM-DD` bullets below for extra notes._
