# Team worklogs — index

Role definitions and onboarding context come from **`data/docs/team-onboarding/`** (canonical) and supporting docs under **`docs/`**.

Each member file leads with a **Cumulative summary** table (**weeks 4–12**): *Week #*, *Major work done this week*, *Total hours spent this week*, *Cumulative total* (running sum from week 4). Below that is a short **role reference** (scope, files, links). Replace or extend table rows with your real hours and tasks.

## Summary table

| Person | Role | Baseline → 4-week target | Primary focus | Typical test ownership (see `scripts/ci_report.py`) |
|--------|------|---------------------------|---------------|-----------------------------------------------------|
| **1** | Platform Lead | 6.5 → 8.5 | API shape, CI/CD, contracts, release quality, benchmarks | `test_api_endpoints`, `test_evaluator`, `test_benchmark_runner`, `test_scenarios` |
| **2** | ReAct owner | 6.0 → 8.0 | G1/G2 loops, traces, stop reasons, workspace streaming, UI trace/monitor | `test_multiagent`, `test_state_validator`, `test_prompt_manager`; shared `test_agent_flow` |
| **3** | RAG owner | 4.5 → 8.0 | Retrieval, citations, knowledge corpus, RAG contract | `test_rag_tools` |
| **4** | Memory owner | 6.5 → 8.2 | Session memory, recall, persistence, episodic/semantic | `test_memory` |
| **5** | Tooling owner | 6.0 → 8.0 | CTI, log parser, sandbox/lab, tool envelopes | `test_tools`, `test_sandbox`; shared `test_agent_flow` |

**Template totals (weeks 4–12 only)** — replace with actuals as you log time:

| Person | Hours W4–12 (example template) |
|--------|--------------------------------|
| 1 — Platform | 91 |
| 2 — ReAct | 90 |
| 3 — RAG | 93 |
| 4 — Memory | 87 |
| 5 — Tooling | 89 |

## Member worklog files

| File | Member |
|------|--------|
| [person-1-platform-lead.md](./person-1-platform-lead.md) | Platform Lead |
| [person-2-react-owner.md](./person-2-react-owner.md) | ReAct owner |
| [person-3-rag-owner.md](./person-3-rag-owner.md) | RAG owner |
| [person-4-memory-owner.md](./person-4-memory-owner.md) | Memory owner |
| [person-5-tooling-owner.md](./person-5-tooling-owner.md) | Tooling owner |

## Related documentation

- `data/docs/team-onboarding/team-onboarding-summary.md` — team structure and score targets  
- `docs/pr-checklist.md` — merge requirements (contracts, CI)  
- `docs/contracts.md`, `docs/trace-contract.md`, `docs/tool-contracts.md` — cross-team contracts  
- `docs/release-quality-gate.md` — release checks  
- `docs/test-tracker.md` — test status and exclusions  
- `docs/tooling-runbook.md` — operational tooling notes  

## How to use this folder

1. **Edit the cumulative table** at the top of your file each week (weeks 4–12); keep *Cumulative total* = sum of weekly hours from week 4 through that week.  
2. Use the **role reference** section for scope, key paths, and onboarding links.  
3. **Platform Lead** coordinates contract changes that touch multiple tracks; see `docs/pr-checklist.md` for approval paths.

---

*Generated from `data/docs/team-onboarding/*` and `docs/*`; adjust targets and paths as the repo evolves.*
