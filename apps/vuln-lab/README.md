# OWASP Vulnerable Lab (Educational)

This app is intentionally vulnerable and exists for local learning only.

## Run

```bash
npm --prefix apps/vuln-lab install
LAB_MODE=vulnerable npm --prefix apps/vuln-lab run dev
```

Open:

- `http://127.0.0.1:3100` (vulnerable lab pages)

## CTI Bridge

The lab emits JSONL logs under `data/logs/` and can forward suspicious events to the existing FastAPI CTI service:

- Event mode -> `POST /api/v1/sandbox/analyze`
- Batch mode -> `POST /api/v1/analyze/g1` or `POST /api/v1/analyze/g2`

Environment variables:

- `CTI_API_BASE` (default `http://127.0.0.1:8000`)
- `CTI_BRIDGE_MODE` (`event`, `batch`, `both`)
- `CTI_ANALYZE_MODE` (`g1`, `g2`)
- `CTI_BATCH_SIZE` and `CTI_FLUSH_MS`

## Safety

- The lab refuses to start when `ENVIRONMENT=production`.
- Host defaults to `127.0.0.1`.
