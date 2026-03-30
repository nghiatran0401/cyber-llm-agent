# Docker Setup Guide

This project is designed to run as a three-service Docker Compose stack:

- `api` (FastAPI) on `http://localhost:8000`
- `web` (Next.js) on `http://localhost:3000`
- `lab` (OWASP vulnerable lab + dashboard) on `http://localhost:3100`

## Prerequisites

- Docker Desktop (or Docker Engine + Compose plugin)
- A configured `.env` file in repository root

## First-time setup

### macOS / Linux

```bash
cp .env.example .env
docker compose up --build -d
```

### Windows PowerShell

```powershell
Copy-Item .env.example .env
docker compose up --build -d
```

## Daily commands

Start stack:

```bash
docker compose up -d
```

Follow logs:

```bash
docker compose logs -f
```

Stop stack:

```bash
docker compose down --remove-orphans
```

Hard reset (remove volumes too):

```bash
docker compose down -v --remove-orphans
```

## URLs

- Web workspace: `http://localhost:3000`
- API docs: `http://localhost:8000/docs`
- Lab app: `http://localhost:3100`
- Lab dashboard scenarios API: `http://localhost:3100/api/dashboard/scenarios`

## Optional Make shortcuts

If your environment has `make` installed:

- `make docker-up`
- `make docker-down`
- `make docker-reset`
- `make docker-logs`
- `make clean` (removes local cache/install artifacts)
