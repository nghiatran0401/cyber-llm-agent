# Cyber LLM SOC Assistant

Production-oriented AI assistant for security teams. It analyzes logs, predicts likely attack progression, and generates practical incident response recommendations with transparent reasoning.

## Why This Exists

Security operations teams face alert fatigue and slow triage. This project helps by:

- turning raw logs into structured, actionable findings
- showing live step-by-step agent reasoning for trust and explainability
- supporting training workflows with an optional local OWASP sandbox

## Core Capabilities

- **G1 Single Agent**
  - Tool-enabled analysis with adaptive model routing
  - Memory/session support for better multi-turn context
- **G2 Multiagent Workflow**
  - `LogAnalyzer` -> `ThreatPredictor` -> `IncidentResponder` -> `Orchestrator`
  - Each step contributes to a final executive-ready summary
- **FastAPI Backend**
  - API endpoints for G1/G2/chat/sandbox workflows
  - Optional API key auth + rate limiting middleware
  - Health (`/api/v1/health`) and readiness (`/api/v1/ready`) probes
  - OpenAPI docs for typed integration (`/api/v1/*`)
- **Next.js Web Frontend**
  - Next.js + Tailwind + TypeScript app in `apps/web`
  - Unified ChatGPT-style workspace combining chat + log analysis
  - OWASP sandbox view with live trace

## Architecture (High Level)

```text
Input (Logs / Chat / Sandbox Event)
    -> Agent Runtime (G1 or G2 pipeline)
    -> Findings + Threat Prediction + Response Plan
```

## G1 End-to-End Path (Single Agent)

This section is the practical "how G1 works" guide for teammates and evaluators.

### G1 endpoints

- `POST /api/v1/analyze/g1` - synchronous JSON analysis response
- `POST /api/v1/chat` with `mode=g1` - synchronous chat-style response
- `POST /api/v1/workspace/stream` with `mode=g1` - streaming SSE progress + final output
- `POST /api/v1/sandbox/analyze` with `mode=g1` - sandbox event converted to analysis prompt, then routed through G1

### Request lifecycle

1. API middleware applies optional auth/rate-limit checks.
2. Input is validated and sanitized.
3. Prompt injection guard runs first (`SafetyGuard` trace step).
4. Service prompt template is applied (`PROMPT_VERSION_G1`).
5. `G1Agent` loads session memory context and builds an augmented prompt.
6. Adaptive routing picks fast/strong model via semantic intent routing.
7. Agent executes with tools:
   - `LogParser`
   - `CTIFetch` (AlienVault OTX)
   - `RAGRetriever` (Pinecone-backed semantic retrieval)
8. Post-processing applies:
   - structured output parse
   - critic validation
   - action gating for high-risk decisions
   - output policy guard
9. API returns final content + metadata (`stop_reason`, model, timing, token/cost estimates, optional trace).

### Two prompt layers in G1

- Service-layer analysis prompt version (`PROMPT_VERSION_G1`, typically `prompts/security_analysis_v2.txt`)
- Agent system prompt (`prompts/g1/system_prompt.txt`)

### Session and memory behavior

- `session_id` enables continuity across turns.
- Memory state is persisted under `data/sessions/`.
- Memory capacity/recall is controlled via `MEMORY_*` and `SESSION_RETENTION_DAYS`.

### `stop_reason` values you will see

- `completed` - normal completion
- `needs_human` - blocked/escalated by injection guard, critic/action gate, or output policy guard
- `budget_exceeded` - runtime/step budget reached
- `error` - request-level failure (for example auth/rate-limit or unhandled API error paths)

### Streaming vs non-streaming

- `analyze/g1` and `chat` are synchronous.
- `workspace/stream` emits step events (`trace`) and a final event over SSE.

## Quick Start (Local)

### 1) Prerequisites

- Python **3.10–3.13** (`langchain-pinecone` does not support 3.14+ yet; use 3.12 if unsure)
- OpenAI API key
- Node.js 20+ (for Next.js frontend)
- Docker + Docker Compose plugin (recommended for team setup)

### 2) Configure environment

```bash
cp .env.example .env
# Update .env values (OPENAI_API_KEY is required)
```

`.env` is the single source of truth for app configuration.

### 3) Install and validate

```bash
make install
make install-web
make test
make test-web
make benchmark
make benchmark-report
make smoke
make smoke-checklist
```

### 3.1) Fresh cleanup (remove installed/cache artifacts)

Use this whenever you want to reset local generated artifacts before reinstalling:

```bash
make clean
```

### 4) Run the API service

```bash
make run-api
```

Open `http://127.0.0.1:8000/docs` for OpenAPI docs.

### 5) Run the Next.js frontend

```bash
make install-web
cp apps/web/.env.local.example apps/web/.env.local
make run-web
```

Open `http://127.0.0.1:3000`.

The web app expects the FastAPI backend at `NEXT_PUBLIC_API_BASE_URL` (default `http://127.0.0.1:8000`).

### 6) Run the OWASP vulnerable lab + plain dashboard

```bash
make install-lab
make run-lab
```

Open:

- `http://127.0.0.1:3100` for vulnerable pages
- `http://127.0.0.1:3100/dashboard` for live telemetry/detections

## Run with Docker (recommended for macOS + Windows teams)

### Option A: single command path with Make

```bash
cp .env.example .env
make docker-up
```

For Windows PowerShell:

```powershell
Copy-Item .env.example .env
make docker-up
```

Open:

- `http://localhost:3000` (Next.js web)
- `http://localhost:8000/docs` (FastAPI docs)

Stop containers:

```bash
make docker-down
```

Reset containers + volumes for a full clean restart:

```bash
make docker-reset
```

### Option B: pure Docker Compose commands

```bash
cp .env.example .env
docker compose up --build -d
docker compose logs -f
docker compose down --remove-orphans
```

The compose stack runs both:

- `api` (`services.api.main:app`) on `8000`
- `web` (Next.js production server) on `3000`

Detailed operator notes are in `docs/docker-setup.md`.

## Configuration Notes

- Policy gates reference: `docs/policy-gates.md` (kept production guardrails and return behavior)
- `ENVIRONMENT=production` forces sandbox off by validation rules.
- `ENABLE_SANDBOX=true` is for local training/non-production use.
- Sandbox API routes return `403` when sandbox is disabled.
- API key protection can be enabled with `API_AUTH_ENABLED=true` and `API_AUTH_KEY=<secret>`.
- Basic rate limiting can be enabled with `API_RATE_LIMIT_ENABLED=true`.
- Agent run-loop safety caps are controlled by:
  - `MAX_AGENT_STEPS`
  - `MAX_RUNTIME_SECONDS`
- Workflow/task caps (mainly multi-step workflow behavior) include:
  - `MAX_TOOL_CALLS`
  - `MAX_WORKER_TASKS`
- Memory retention and recall controls:
  - `MEMORY_MAX_EPISODIC_ITEMS`
  - `MEMORY_MAX_SEMANTIC_FACTS`
  - `MEMORY_RECALL_TOP_K`
  - `SESSION_RETENTION_DAYS`
- Prompt version controls (filenames under `prompts/`; canonical analysis template is `security_analysis_v2.txt`):
  - `PROMPT_VERSION_G1`
  - `PROMPT_VERSION_G2`
- Optional rubric evaluation:
  - `ENABLE_RUBRIC_EVAL`
- Safety/governance guardrails:
  - `ENABLE_PROMPT_INJECTION_GUARD`
  - `ENABLE_OUTPUT_POLICY_GUARD`
  - `MIN_EVIDENCE_FOR_HIGH_RISK`
  - `REQUIRE_HUMAN_APPROVAL_HIGH_RISK`
- Runtime metrics endpoint:
  - `GET /api/v1/metrics`
  - `GET /api/v1/metrics/dashboard` for summary + recent runs
- CTI uses AlienVault OTX only; `OTX_API_KEY` is required. Timeout/retry limits use `CTI_*` settings.
- G1 picks `FAST_MODEL_NAME` vs `STRONG_MODEL_NAME` from semantic risk routing (always on).
- RAG (Pinecone semantic retrieval) is always enabled. Put knowledge files under `data/knowledge/`, set `PINECONE_API_KEY` / `PINECONE_INDEX_NAME` in `.env`, then **ingest** those files into Pinecone (see below). The API does **not** auto-ingest on startup; run ingest after you add or change docs, or whenever the index is empty.
- CTI tool input supports:
  - threat-type queries (example: `ransomware`)
  - IOC queries (example: `ioc:ip:1.2.3.4`, `ioc:domain:example.com`, `ioc:url:https://bad.example`, `ioc:hash:<sha256>`)
- Do **not** commit real secrets (`.env` is ignored).

### Local RAG quick check

1. Add one or more `.md`/`.txt` knowledge files under `data/knowledge/`.
2. Configure Pinecone credentials in `.env` (`PINECONE_API_KEY`, `PINECONE_INDEX_NAME`).
3. **Ingest into Pinecone** (required before retrieval can see new files; repeat when knowledge changes):

   ```bash
   # From the repository root, with dependencies installed (`make install`)
   PYTHONPATH=. python -c "from src.tools.rag_tools import ingest_knowledge_base; print(ingest_knowledge_base())"
   ```

4. Ask a G1/G2 question containing known terms from those files.
5. Confirm the answer includes retrieval citations from the `RAGRetriever` tool output.

## OTX Rollout Guidance

- Keep a valid `OTX_API_KEY` in each environment.
- Enable and verify OTX first in local dev, then staging, then production.
- Monitor timeout/rate-limit trends before broad rollout (`CTI_REQUEST_TIMEOUT_SECONDS`, `CTI_MAX_RETRIES`).
- When OTX is unavailable, CTI returns a deterministic fallback report instead of failing the workflow.
- Quick runtime verification (from repo root, in your app env):

  ```bash
  PYTHONPATH=. python -c "from src.tools.cti_tool import fetch_cti_intelligence; print(fetch_cti_intelligence('ioc:ip:8.8.8.8'))"
  ```

  Expect `Source: AlienVault OTX` for a healthy live lookup.

## Quality Gate

CI pipeline (`.github/workflows/ci.yml`) runs:

- compile checks (`make lint`)
- full tests (`make test`)
- benchmark evaluation (`make benchmark`)
- frontend API integration tests (`make test-web`)
- smoke tests (`make smoke`)

For one-command endpoint checklist validation (auth/rate-limit/RAG + core API routes), run:

```bash
make smoke-checklist
```

## Benchmark Evaluation

Canonical benchmark dataset:

- `data/benchmarks/threat_cases.json`
- `data/benchmarks/threat_cases_lab.json` (OWASP lab simulation cases)

Run benchmark locally (CI-safe deterministic mode):

```bash
make benchmark
make benchmark-report
```

Artifacts are written to:

- `data/benchmarks/results/latest.json`
- `data/benchmarks/results/latest.md`
- timestamped files under `data/benchmarks/results/`

### Real-LLM staging benchmark run

Use this for assignment/demo evidence with real model calls:

```bash
BENCHMARK_MODE=real-llm \
BENCHMARK_AGENT_MODE=g1 \
BENCHMARK_PROVIDER=openai \
make benchmark
```

For G2:

```bash
BENCHMARK_MODE=real-llm \
BENCHMARK_AGENT_MODE=g2 \
BENCHMARK_PROVIDER=openai \
make benchmark
```

Required environment:

- `OPENAI_API_KEY`
- `OTX_API_KEY`

Reference methodology and evidence guidance:

- `docs/benchmark-evaluation.md`

## Repository Layout

```text
src/
  agents/
    g1/              # single-agent modules
    g2/              # multiagent workflow modules
  config/            # centralized settings and validation
  sandbox/           # local OWASP event simulation
  tools/             # log parser + CTI tools
  utils/             # memory, session, evaluator, logging
services/api/        # FastAPI endpoints wrapping G1/G2
apps/web/            # Next.js + Tailwind + TypeScript frontend
apps/vuln-lab/       # Old-school HTML/CSS/JS vulnerable learning lab + dashboard
tests/
```

## Open-Source Readiness

- Security policy: `SECURITY.md`
- Contributing guide: `CONTRIBUTING.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- License: `LICENSE` (MIT)

## License

MIT
