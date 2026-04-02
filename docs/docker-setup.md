# Docker Setup Guide

The recommended way to run the full stack (API + web + OWASP lab) is [Docker Compose](https://docs.docker.com/compose/) from the repository root.

## What runs

| Service | Image context | Port | Description |
|---------|---------------|------|-------------|
| `api` | Root `Dockerfile` | 8000 | FastAPI (`services.api.main:app`) |
| `web` | `apps/web` | 3000 | Next.js (`next start` after build) |
| `lab` | `apps/vuln-lab` | 3100 | Intentionally vulnerable training lab + dashboard |

The API container mounts host `./data/sessions`, `./data/logs`, and `./data/knowledge` so sessions, logs, and the RAG knowledge corpus stay in sync with the repo. The lab container mounts `./data/logs` to `/lab-data` for JSONL telemetry (the lab image does not include the full monorepo, so paths are set via `LAB_*_FILE` in `docker-compose.yml`).

## Prerequisites

- Docker Desktop (macOS/Windows) or Docker Engine + Compose plugin (Linux)
- A root `.env` file (copy from `.env.example` and fill in secrets)

## First-time setup

### macOS / Linux

```bash
cp .env.example .env
# Edit .env: OPENAI_API_KEY, OTX_API_KEY, PINECONE_API_KEY (required at API startup)
docker compose up --build -d
```

### Windows PowerShell

```powershell
Copy-Item .env.example .env
docker compose up --build -d
```

## Daily commands

| Goal | Command |
|------|---------|
| Start (reuse build) | `docker compose up -d` |
| Follow logs | `docker compose logs -f` |
| Stop | `docker compose down --remove-orphans` |
| Hard reset (containers + anonymous volumes Compose created) | `docker compose down -v --remove-orphans` |

## URLs

- Web workspace: `http://localhost:3000`
- API docs: `http://localhost:8000/docs`
- Lab: `http://localhost:3100`
- Lab dashboard (JSON): `http://localhost:3100/api/dashboard/scenarios`

## Compose-specific behavior

- **`CTI_API_BASE` for the lab** is fixed to `http://api:8000` inside Compose so the lab reaches the API by service name. Your root `.env` may still use `CTI_API_BASE=http://127.0.0.1:8000` for local `make run-lab` on the host; that value is not used for the lab service in Compose.
- **Frontend public URLs** default to `http://localhost:8000` and `http://localhost:3100` for `NEXT_PUBLIC_*` at build time. Override in `.env` if your browser cannot use `localhost`.

## Single-container API only

To build and run only the Python API image (no Compose):

```bash
make docker-build
make docker-run
```

This maps port 8000 and passes `--env-file .env`.

## Make targets (optional)

See the root `Makefile` for `docker-build`, `docker-run`, `docker-up`, `docker-down`, `docker-reset`, `docker-logs`, and local dev targets (`run-api`, `run-web`, `run-lab`).
