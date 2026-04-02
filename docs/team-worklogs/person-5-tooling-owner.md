# Worklog — Person 5 (Tooling owner)

## Cumulative summary (weeks 4–12)

*Cumulative total = sum of hours from week 4 through that row.*

| Week # | Major work done this week | Total hours spent this week | Cumulative total |
|--------|---------------------------|-----------------------------|------------------|
| 4 | Freeze tool output envelope (`ok` / `data` / `error` / `meta`); write unhappy-path matrix for CTI + log parser | 10 | 10 |
| 5 | Refactor CTI retries/backoff; return explicit error codes/messages for agent consumption | 9 | 19 |
| 6 | Tighten log parser contract; add tests for malformed / huge / binary-adjacent inputs | 12 | 31 |
| 7 | Align `vuln-lab` with Compose (`CTI_API_BASE`, bridge mode); smoke dashboard + telemetry paths | 10 | 41 |
| 8 | Regression tests for sandbox analyze/simulate routes; define telemetry fields (success/fail/latency) | 11 | 52 |
| 9 | Sync tool step labels with ReAct traces; consistent naming for tool failures in UI | 10 | 62 |
| 10 | Flake hunt in `test_tools` / `test_sandbox`; stabilize OTX mocks | 8 | 70 |
| 11 | Update `docs/tooling-runbook.md`; draft tooling reliability report | 10 | 80 |
| 12 | Final lab ↔ API demo scenario; handover notes for CTI key rotation and lab env | 9 | 89 |

---

## Role reference

| Field | Value |
|-------|--------|
| **Role** | Tooling owner — CTI, log parser, sandbox/lab, tool contracts |
| **Track maturity (onboarding)** | 6.0 / 10 → **target 8.0** in 4 weeks |
| **CI test owner (typical)** | `test_tools`, `test_sandbox`; shared `test_agent_flow` |

### Mission (plain English)

Standardize **tool outputs**, **errors**, retries, and **lab** behavior so agents and UI get **predictable** evidence—not fragile strings.

### Key files

- `src/tools/log_parser_tool.py`, `src/tools/cti_tool.py`  
- `apps/vuln-lab/` (server, routes, env)  
- `tests/unit/test_tools.py`, `tests/unit/test_sandbox.py`  
- `docs/tool-contracts.md`, `docs/tooling-runbook.md`  

### References

- `data/docs/team-onboarding/person-5-tooling-owner.md`  

---

## Dated log (optional)

_Add `### YYYY-MM-DD` bullets below for extra notes._
