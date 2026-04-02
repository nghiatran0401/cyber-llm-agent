# Cyber LLM SOC Assistant — Project Context

## What the product does
- Production-oriented AI assistant for security operations. Takes free-form questions plus optional log files and returns incident-grade analysis: findings, likely attack progression, and concrete response actions.
- Two runtime modes: **G1 single-agent** (tool-enabled, memory-aware) and **G2 multi-agent** (orchestrated LangGraph pipeline). Both run behind a FastAPI service and are surfaced through a Next.js web UI.
- Optional OWASP vulnerable lab + sandbox lets you generate synthetic events, stream them into logs, and analyze them with the same agents.

## Agent modes and collaboration
### G1 — Single, tool-enabled, memory agent (`src/agents/g1`)
- **Routing:** `AdaptiveSecurityAgent` picks a fast vs strong LLM based on semantic risk intent; tool stack stays the same.
- **Tools:** `LogParser` (Grok-based log extraction), `CTIFetch` (AlienVault OTX), optional `RAGRetriever` (local MITRE context) when `ENABLE_RAG=true`.
- **Memory:** `StatefulSecurityAgent` wraps the adaptive agent with conversation memory (`ConversationMemory`) and session persistence (`SessionManager`), so repeated calls can accumulate context and long‑term facts.
- **Flow:** input is validated → prompt template applied → model routed → tools invoked inside the LangChain agent → response structured and policy-gated by the API layer.

### G2 — Multi-agent pipeline (`src/agents/g2`)
- **Roles:** `LogAnalyzer` → `ThreatPredictor` → `IncidentResponder` → `Orchestrator`; each has its own system prompt (`multiagent_config.py`).
- **Execution graph:** `graph.py` builds a LangGraph with ordered edges; default LLM is the fast model. `runner.py` offers two entrypoints: `run_multiagent_assessment` (one-shot) and `run_multiagent_with_trace` (sequential with UI-visible traces and budgets).
- **Node behaviors (`nodes.py`):**
  - `log_analyzer_node`: loads/normalizes logs (or reads files via `parse_system_log`), pulls RAG context when enabled.
  - `threat_predictor_node`: infers threat theme, fetches OTX CTI, drafts likely attacker next steps.
  - `plan_worker_tasks` + `run_worker_task`: dynamic worker list (identity, appsec, network, threat hunt) derived from evidence; each worker LLM call produces targeted reports.
  - `incident_responder_node`: converts predictions + worker outputs into containment/recovery actions.
  - `verifier_node`: checks incident response against evidence; may trigger a single retry.
  - `orchestrator_node`: fuses all outputs (analysis, prediction, CTI, RAG, verifier feedback) into the final report.
- **State:** `AgentState` (typed dict) carries logs, evidence, planner outputs, and final report; traces (`MultiagentStepTrace`) feed the UI.
- **Budgets:** bounded by `MAX_AGENT_STEPS`, `MAX_RUNTIME_SECONDS`, and `MAX_WORKER_TASKS`; stop reasons bubble back to the API.

## Supporting subsystems
- **Tools (`src/tools`)**
  - `log_parser_tool.py`: Safe file resolution under `data/logs`, Grok parsing, keyword filtering.
  - `cti_tool.py`: AlienVault OTX lookups for threat keywords or IOC queries (`ioc:ip|domain|hostname|url|hash:<value>`), with retries/backoff and fallback report.
  - `rag_tools.py`: Builds and queries a local Chroma MITRE index; returns scored context snippets with citations.
- **RAG stack (`src/rag`)**: ingestion (`ingestion/index_builder.py`, `mitre_loader.py`), retrieval + rerankers, small agent helpers, CLI entrypoint (`src/rag/cli/main.py`), and scripts (`scripts/rag_build_index.py`, `rag_verify_index.py`, `rag_cli.py`).
- **Memory & sessions (`src/utils/memory_manager.py`, `session_manager.py`)**: message buffers or summaries, episodic and semantic memory, persisted under `data/sessions/`.
- **Guardrails (`services/api/guardrails.py`)**: input size limits, prompt-injection detection, output denylist, high-risk action gating based on evidence counts and human-approval flags, response trimming.
- **Prompt management (`src/utils/prompt_manager.py`, `prompts/`)**: versioned templates (e.g., `security_analysis_v2.txt` plus per-role/step prompts under `prompts/g1`, `prompts/g2`, `prompts/service`, `prompts/benchmark`).
- **Benchmarking (`src/benchmarking`, `data/benchmarks`, `scripts/run_benchmark.py`)**: offline deterministic agent vs real-LLM runs, F1/latency metrics, markdown + JSON artifacts.

## API surface (`services/api`)
- **Entrypoint:** `main.py` (FastAPI). Startup validation uses `Settings.validate`.
- **Endpoints:**
  - `/api/v1/health`, `/api/v1/ready`
  - `/api/v1/analyze/g1` and `/api/v1/analyze/g2` for single-turn analyses; `/api/v1/chat` for conversational mode (G1 or G2).
  - `/api/v1/workspace/stream` (server-sent events) streams trace + final output to the web UI.
  - Sandbox: `/api/v1/sandbox/scenarios`, `/api/v1/sandbox/simulate`, `/api/v1/sandbox/analyze`, `/api/v1/sandbox/live-log`.
  - Metrics: `/api/v1/metrics`, `/api/v1/metrics/dashboard`, recent detections feed.
- **Service layer:** `g1_service.py`, `g2_service.py`, `sandbox_service.py` perform validation, prompt selection, model routing, rubric scoring, policy gates, and structured report building (`response_parser.py`). Agent instances are cached with TTL and size caps.
- **Security/perf knobs:** optional API key auth + rate limiting, token/cost estimation, tool-call accounting, run traces, stop reasons, and rubric metadata returned in `ResponseMeta`.

## Frontend (`apps/web`)
- Next.js + Tailwind SPA offering a unified “Workspace” chat: select mode (G1/G2), paste text, attach `.txt/.log/.json/.jsonl` files, and watch live progress.
- Uses `/api/v1/workspace/stream` to show **Live Monitor** (phase progression) and **Technical Trace** (per-step summaries) while streaming assistant answers into the chat thread.
- Components and libs: `components/TracePanel`, `lib/api.ts` for streaming, `lib/monitor-state` for phase badges/progress.

## Sandbox & vulnerable lab
- **OWASP sandbox (`src/sandbox/owasp_sandbox.py`, `services/api/sandbox_service.py`):** predefined scenarios (SQLi, XSS, brute force). Generates structured events, optionally appends to `data/logs/live_web_logs.jsonl`, converts to analysis text, and routes through G1 or G2.
- **Training lab (`apps/vuln-lab`):** static vulnerable site + telemetry dashboard used alongside the sandbox flows; started separately via Make/NPM commands noted in README.

## Configuration & data
- Central settings in `src/config/settings.py`; reads `.env` / `.env.example`. Controls model names, routing, safety budgets, CTI/RAG keys, rate limits, sandbox toggle, memory limits.
- Data directories (auto-created): `data/logs` (ingested or live logs), `data/knowledge` (RAG sources), `data/cti_feeds`, `data/benchmarks/results`, `data/sessions` (conversation state), `data/mitre` (MITRE corpus).
- Prompt files live under `prompts/`; `.env` is the single source of truth for runtime config. Dockerfile and Makefile wrap local/dev usage.

## Tests & QA
- Unit and integration tests under `tests/` plus targeted checks (`tests/test_scenarios.py`, `tests/test_benchmark_runner.py`). Smoke checklist in `scripts/smoke_checklist.py`.
- CI (see `.github/workflows`) runs lint, tests, benchmarks, and smoke flows; mirrors Make targets in README.

## Repository map (top-level)
- `services/api/` — FastAPI app, endpoints, guardrails, service runners, schemas.
- `src/agents/` — G1 single-agent stack, G2 multi-agent pipeline, shared intent routing.
- `src/tools/` — Log parser, CTI fetcher, RAG bridge tools.
- `src/rag/` — RAG ingestion/retrieval agents and utilities.
- `src/utils/` — Logging, prompts, memory/session managers, state validation.
- `src/sandbox/` — OWASP sandbox event generator utilities.
- `apps/web/` — Next.js frontend for chat + log analysis UI.
- `apps/vuln-lab/` — Vulnerable training lab and dashboard.
- `prompts/` — Prompt templates for agents, roles, benchmarks, service wrappers.
- `data/` — Logs, knowledge base, CTI caches, sessions, benchmarks, MITRE corpus.
- `scripts/` — CLI helpers for RAG, benchmarks, smoke checks.
- `tests/` — Unit/integration coverage.

## How the pieces fit together
1) A user sends a question and/or logs (via API or web UI).  
2) The API layer validates input, picks G1 or G2 flow, selects prompts, and enforces guardrails.  
3) Agents call shared tools: log parsing for evidence, CTI for threat intel, optional RAG for local knowledge.  
4) G1 returns a structured, evidence-aware single-agent answer with memory carryover; G2 runs the multi-role graph, verifies, and orchestrates a final executive summary.  
5) Results, traces, tool stats, and rubric scores stream back to the UI and metrics endpoints for observability.
