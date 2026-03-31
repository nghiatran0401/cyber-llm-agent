# Cyber LLM SOC Assistant

An AI assistant for security operations: it turns logs and natural-language questions into structured findings, threat-oriented predictions, and incident-response style guidance—with **step-by-step traces** so analysts can see how conclusions were reached.

---

## Who this is for

- **SOC / IR analysts** triaging alerts and logs  
- **Students and builders** learning agentic security workflows (optional OWASP lab)  
- **Teams** who want a small but real **FastAPI + Next.js** codebase with two agent modes (single-agent vs multi-step workflow)

**Team onboarding** (roles, tracks, honest status): [`docs/team-onboarding/team-onboarding-summary.md`](docs/team-onboarding/team-onboarding-summary.md).

---

## What you get (at a glance)

| Piece | What it does |
|-------|----------------|
| **G1** | Single agent with tools (log parser, CTI, RAG), memory/sessions, adaptive model routing |
| **G2** | Multi-agent pipeline: log analysis → threat prediction → incident response → orchestrated summary |
| **API** | FastAPI service under `services/api/` — analyze, chat, streaming workspace, sandbox, metrics, health |
| **Web** | Next.js app in `apps/web` — workspace UI with traces |
| **Lab** | Deliberately vulnerable OWASP-style app in `apps/vuln-lab` (training only; not for production) |

Frozen HTTP and tool contracts live in [`docs/contracts.md`](docs/contracts.md) and [`docs/tool-contracts.md`](docs/tool-contracts.md).

---

## Prerequisites

- **Python 3.10–3.13** (see `requirements.txt` header; some deps exclude 3.14+ today)  
- **Node.js 20+** (for the web app and lab)  
- **Docker + Docker Compose** (recommended for the full three-service stack)  
- **API keys** (see below): OpenAI, AlienVault OTX, Pinecone (RAG)

---

## Configuration (start here)

1. Copy the template and edit values:

   ```bash
   cp .env.example .env
   ```

2. **Required in `.env`** (validated when the API starts — see `src/config/settings.py`):

   - `OPENAI_API_KEY`
   - `OTX_API_KEY`
   - `PINECONE_API_KEY` and `PINECONE_INDEX_NAME`

3. **Local web app** (when not using Docker for the frontend):

   ```bash
   cp apps/web/.env.local.example apps/web/.env.local
   ```

   Point `NEXT_PUBLIC_API_BASE_URL` at your API (default `http://127.0.0.1:8000`). If you enable `API_AUTH_ENABLED`, set `NEXT_PUBLIC_API_KEY` to match `API_AUTH_KEY`.

`.env.example` is kept in sync with the Python settings model; optional keys are documented inline there.

---

## Running the system

### Option A — Docker Compose (recommended)

Runs **API (8000)**, **web (3000)**, and **lab (3100)** together.

```bash
cp .env.example .env
# fill secrets, then:
docker compose up --build -d
```

- Web: `http://localhost:3000`  
- API docs: `http://localhost:8000/docs`  
- Lab: `http://localhost:3100`  

**Operator details** (volumes, lab ↔ API networking, URL overrides): [`docs/docker-setup.md`](docs/docker-setup.md).

**API-only container** (no Compose):

```bash
make docker-build
make docker-run
```

### Option B — Local development (no Docker)

Install dependencies, then run each process in its own terminal:

```bash
make install          # Python deps
make install-web      # Next.js deps
make install-lab      # Lab deps (optional)

make run-api          # http://127.0.0.1:8000
make run-web          # http://127.0.0.1:3000
make run-lab          # http://127.0.0.1:3100 (optional)
```

---

## Everyday commands (Make)

| Command | Purpose |
|---------|---------|
| `make lint` | Byte-compile critical Python packages (fast sanity check) |
| `make test` | Full pytest suite (includes integration tests if not skipped) |
| `make test-ci` | Same set as CI: all tests except `tests/integration/test_agent_flow.py` (needs real `OPENAI_API_KEY`) |
| `make test-web` | Frontend unit tests (Vitest) |
| `make benchmark` / `make benchmark-report` | Offline benchmark pipeline (CI-safe defaults) |
| `make smoke` | Quick compile + memory/session smoke tests |
| `make smoke-checklist` | Scripted API checklist (auth, rate limit, core routes) |
| `make ci` | Lint + CI tests + benchmark + smoke + web tests (heavy; mirrors most of CI locally) |
| `make validate-traces` | Trace validation helper (see `scripts/validate_traces.py`) |
| `make release-gate` | Release checklist script (see `scripts/release_gate.py`) |
| `make rag-build-index` / `make rag-verify` | Local MITRE Chroma index (when `RAG_VECTOR_BACKEND=chroma`) |

**CI on GitHub** (Python 3.10 + 3.11): `.github/workflows/ci.yml` runs `make lint`, `make test-ci`, `make benchmark`, memory smoke, and web tests.

---

## How G1 works (short path)

1. Request hits FastAPI → optional auth / rate limits (`services/api/middleware.py`).  
2. Input is validated; prompt-injection guard may return `stop_reason=needs_human`.  
3. G1 loads the prompt version (`PROMPT_VERSION_G1`), session memory, and runs the agent loop with tools.  
4. Structured report + **critic** + **action gating** + **output policy** run before the response is returned.  
5. Response uses the standard envelope (`ApiResponse` in `services/api/schemas.py`).

**Endpoints:** `POST /api/v1/analyze/g1`, `POST /api/v1/chat` (`mode=g1`), `POST /api/v1/workspace/stream` (SSE), `POST /api/v1/sandbox/analyze` (when sandbox is enabled).

**`stop_reason` values:** `completed`, `needs_human`, `budget_exceeded`, `blocked`, `error` (see `docs/contracts.md` for the canonical list).

---

## RAG (Pinecone or optional local Chroma)

RAG is **on** by default. The API does **not** ingest documents on startup.

**Default (`RAG_VECTOR_BACKEND=pinecone`):** cloud index over `data/knowledge/`.

1. Add `.md` / `.txt` files under `data/knowledge/`.  
2. Set Pinecone env vars in `.env`.  
3. Ingest (from repo root, with deps installed):

   ```bash
   python3 -c "from src.tools.rag_tools import ingest_knowledge_base; print(ingest_knowledge_base())"
   ```

4. Re-ingest after you change knowledge files or switch indexes.

**Optional (`RAG_VECTOR_BACKEND=chroma`):** local Chroma + sentence-transformers over MITRE-style markdown in `data/mitre/` (see `data/mitre/README.md`). Build with `make rag-build-index` or `python3 scripts/rag_build_index.py`. Pinecone keys are not required when this backend is selected and `ENABLE_RAG=true`. The standalone CLI lives at `scripts/rag_cli.py`.

---

## Sandbox and safety

- `ENABLE_SANDBOX=true` is for **non-production** training. In `ENVIRONMENT=production`, sandbox stays off by validation rules.  
- Sandbox routes return **403** when disabled.  
- Policy and gate reference: [`docs/policy-gates.md`](docs/policy-gates.md).  
- Release checklist: [`docs/release-quality-gate.md`](docs/release-quality-gate.md).

---

## Benchmarks

- Datasets: `data/benchmarks/threat_cases.json`, `data/benchmarks/threat_cases_lab.json`  
- Offline (deterministic, CI-safe):

  ```bash
  make benchmark
  make benchmark-report
  ```

- Real LLM (local only; needs keys):

  ```bash
  BENCHMARK_MODE=real-llm BENCHMARK_AGENT_MODE=g1 BENCHMARK_PROVIDER=openai make benchmark
  ```

More methodology: [`docs/benchmark-evaluation.md`](docs/benchmark-evaluation.md).

---

## Repository layout

```text
src/
  agents/g1/          # single-agent runtime
  agents/g2/          # multi-agent workflow
  agents/shared/      # shared helpers (e.g. intent routing)
  config/             # Settings (env → `Settings`)
  sandbox/            # OWASP event simulation (API-facing)
  tools/              # log parser, CTI, RAG, envelopes
  utils/              # memory, sessions, evaluator, logging
services/api/         # FastAPI app (routes, services, guardrails)
apps/web/             # Next.js frontend
apps/vuln-lab/        # training lab (Express)
tests/                # unit tests + integration (API key gated)
scripts/              # benchmark, CI test runner, smoke, gates
data/                 # knowledge, benchmarks, logs, sessions (runtime artifacts)
prompts/              # prompt templates referenced by Settings
```

---

## Contributing and policies

- [`CONTRIBUTING.md`](CONTRIBUTING.md)  
- PR checklist: [`docs/pr-checklist.md`](docs/pr-checklist.md)  
- Security: [`SECURITY.md`](SECURITY.md)  
- Code of conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)  
- License: [MIT](LICENSE)

---

## License

MIT
