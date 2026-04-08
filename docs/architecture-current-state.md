# Architecture Current State (G1/G2)

This is a plain-language snapshot of what is actually implemented right now.

## G1 (single-agent path)

G1 is a tool-enabled LangChain agent with session memory and service-level guardrails.

### Runtime flow

1. Validate and sanitize input.
2. Detect prompt-injection markers (string-match heuristic).
   - If detected, return early with `stop_reason=needs_human` and skip LLM execution.
3. Resolve prompt version (`PROMPT_VERSION_G1`).
4. Route model fast vs strong.
   - Service computes route for trace.
   - Agent backend also routes by semantic intent.
5. Create and run G1 agent (tools: `log_parser`, `cti_fetch`, `rag_retriever`).
6. Apply service-layer review:
   - structured report parse,
   - critic validation,
   - action gating,
   - output policy guard.
7. Score output with rubric evaluator (if enabled).

## G2 (multi-agent path)

G2 is a hybrid multi-agent workflow:

- LangGraph runs each core specialist node.
- A Python runner controls the full sequence, retries, and budgets.

### Runtime flow

`LogAnalyzer -> WorkerPlanner -> ThreatPredictor -> WorkerTask(s) -> IncidentResponder -> Verifier -> (optional IncidentResponderRetry) -> Orchestrator`

### Why not full LangGraph (today)

- Worker tasks are dynamic (count/type changes per incident).
- Verifier has custom retry/stop behavior.
- Budget checks and live trace streaming happen at each step.
- Runner logic makes these controls simpler and easier to debug.

## Shared controls in both G1 and G2

- Input validation + sanitization
- Prompt-injection short-circuit to `needs_human`
- Action gating for high-risk outputs
- Output policy denylist guard
- Runtime budget tracking with deterministic stop reasons
- Prompt versioning via env config
- Trace steps for UI explainability

## Demo surfaces (minimal UX)

- **Next.js `/sandbox`** (`apps/web/app/sandbox/page.tsx`): **live monitor for vuln-lab.** The browser polls the lab’s dashboard (`GET …/api/dashboard/system-logs` via `NEXT_PUBLIC_LAB_BASE_URL`). When a line has `attack_detected`, it can **auto-run** or you can click **Analyze latest attack**; analysis uses the same **`POST /api/v1/analyze/g1` or `g2`** path as the rest of the product (log text as `input`), with traces in the UI.
- **Vulnerable lab** (`apps/vuln-lab`, port 3100): minimal storefront (**login** for SQLi + failed-login / brute-force signals, **search** for reflected XSS). Dashboard scenario catalog: `apps/vuln-lab/src/scenarios.js`.
- **Diagrams**: `docs/graph1.svg` (system), `docs/graph2.svg` (G1 vs G2 paths).
