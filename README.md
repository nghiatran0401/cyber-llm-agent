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

## Quick Start (Local)

### 1) Prerequisites

- Python 3.10+
- OpenAI API key
- Node.js 20+ (for Next.js frontend)
- Docker (optional, recommended)

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

Replay a repeatable demo flow (with API + lab running):

```bash
python scripts/run_lab_demo.py
```

## Run with Docker

```bash
make docker-build
make docker-run
```

The container runs the FastAPI backend and reads runtime config from `.env`.

## Configuration Notes

- `ENVIRONMENT=production` forces sandbox off by validation rules.
- `ENABLE_SANDBOX=true` is for local training/non-production use.
- Sandbox API routes return `403` when sandbox is disabled.
- API key protection can be enabled with `API_AUTH_ENABLED=true` and `API_AUTH_KEY=<secret>`.
- Basic rate limiting can be enabled with `API_RATE_LIMIT_ENABLED=true`.
- Agent run-loop safety caps are controlled by:
  - `MAX_AGENT_STEPS`
  - `MAX_TOOL_CALLS`
  - `MAX_RUNTIME_SECONDS`
  - `MAX_WORKER_TASKS`
- Memory retention and recall controls:
  - `MEMORY_MAX_EPISODIC_ITEMS`
  - `MEMORY_MAX_SEMANTIC_FACTS`
  - `MEMORY_RECALL_TOP_K`
  - `SESSION_RETENTION_DAYS`
- Prompt version controls:
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
- `CTI_PROVIDER=otx` enables live AlienVault OTX CTI feeds.
- `OTX_API_KEY` is required and CTI requests use timeout/retry guardrails.
- Local RAG can be enabled with `ENABLE_RAG=true` and knowledge files under `data/knowledge/`.
- RAG retrieval supports `lexical`, `semantic`, and `hybrid` modes:
  - `RAG_RETRIEVAL_MODE=hybrid`
  - `RAG_EMBEDDING_DIMS=96`
  - `RAG_SEMANTIC_CANDIDATES=8`
- CTI tool input supports:
  - threat-type queries (example: `ransomware`)
  - IOC queries (example: `ioc:ip:1.2.3.4`, `ioc:domain:example.com`, `ioc:url:https://bad.example`, `ioc:hash:<sha256>`)
- Do **not** commit real secrets (`.env` is ignored).

### Local RAG quick check

1. Add one or more `.md`/`.txt` knowledge files under `data/knowledge/`.
2. Set `ENABLE_RAG=true` in `.env`.
3. Ask a G1/G2 question containing known terms from those files.
4. Confirm the answer includes retrieval citations and scored matches from the `RAGRetriever` tool output.

## OTX Rollout Guidance

- Keep `CTI_PROVIDER=otx` with a valid key in each environment.
- Enable and verify OTX first in local dev, then staging, then production.
- Monitor timeout/rate-limit trends before broad rollout (`CTI_REQUEST_TIMEOUT_SECONDS`, `CTI_MAX_RETRIES`).
- When OTX is unavailable, CTI returns a deterministic fallback report instead of failing the workflow.

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
