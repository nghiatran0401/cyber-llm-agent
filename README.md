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
- **Streamlit UI**
  - 3 views: upload logs, interactive chat, OWASP sandbox
  - Live trace for both G1 and G2

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
make test
make smoke
```

### 4) Run the app

```bash
make run-streamlit
```

Open `http://127.0.0.1:8501`.

## Run with Docker

```bash
make docker-build
make docker-run
```

The container reads runtime config from `.env` only.

## Configuration Notes

- `ENVIRONMENT=production` forces sandbox off by validation rules.
- `ENABLE_SANDBOX=true` is for local training/non-production use.
- Do **not** commit real secrets (`.env` is ignored).

## Quality Gate

CI pipeline (`.github/workflows/ci.yml`) runs:

- compile checks (`make lint`)
- full tests (`make test`)
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
ui/streamlit/app.py
tests/
```

## Open-Source Readiness

- Security policy: `SECURITY.md`
- Contributing guide: `CONTRIBUTING.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- License: `LICENSE` (MIT)

## License

MIT
