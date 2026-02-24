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
make smoke
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
- `CTI_PROVIDER=otx` enables live AlienVault OTX CTI feeds.
- `OTX_API_KEY` is required and CTI requests use timeout/retry guardrails.
- CTI tool input supports:
  - threat-type queries (example: `ransomware`)
  - IOC queries (example: `ioc:ip:1.2.3.4`, `ioc:domain:example.com`, `ioc:url:https://bad.example`, `ioc:hash:<sha256>`)
- Do **not** commit real secrets (`.env` is ignored).

## OTX Rollout Guidance

- Keep `CTI_PROVIDER=otx` with a valid key in each environment.
- Enable and verify OTX first in local dev, then staging, then production.
- Monitor timeout/rate-limit trends before broad rollout (`CTI_REQUEST_TIMEOUT_SECONDS`, `CTI_MAX_RETRIES`).
- When OTX is unavailable, CTI returns a deterministic fallback report instead of failing the workflow.

## Quality Gate

CI pipeline (`.github/workflows/ci.yml`) runs:

- compile checks (`make lint`)
- full tests (`make test`)
- frontend API integration tests (`make test-web`)
- smoke tests (`make smoke`)

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
tests/
```

## Open-Source Readiness

- Security policy: `SECURITY.md`
- Contributing guide: `CONTRIBUTING.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- License: `LICENSE` (MIT)

## License

MIT
