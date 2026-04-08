# OWASP Vulnerable Lab (Educational)

Minimal storefront for local demos only: **SQL injection** (login), **XSS** (search), **brute force** (failed logins). The dashboard API exposes the same three scenarios.

## Run

```bash
npm --prefix apps/vuln-lab install
LAB_MODE=vulnerable npm --prefix apps/vuln-lab run dev
```

Open:

- `http://127.0.0.1:3100` (vulnerable lab pages)

## Reset system logs (demo)

`POST /api/dashboard/system-logs/reset` clears the in-memory system log buffer and truncates `LAB_SYSTEM_LOG_FILE` (default `data/logs/vuln_lab_system.log`). The Sandbox **Clear logs & refresh** button calls this so you can re-run attacks from a clean slate.

## Failed-login vs brute-force signal

One invalid password is **not** labeled brute force (still `401`). The lab counts failures **per IP** in a **10-minute** sliding window and only sets `attack_detected` + `bruteForceLogin` from the **3rd** failure onward (override with `LAB_BRUTE_FORCE_THRESHOLD` and `LAB_BRUTE_FORCE_WINDOW_MS`). Successful login (`admin` / `password123`) or SQLi demo clears the counter for that IP. `POST /api/dashboard/system-logs/reset` also clears counters.

## Browser SDK demo (3rd-party embed)

`public/copilot-sdk-demo.js` is included from `index.html` to simulate a customer adding our Copilot after `npm install`: it polls `GET /api/dashboard/system-logs` and calls `window.alert()` when a **new** `attack_detected` row appears (existing rows when the page loads are ignored so you are not spammed). Remove the script tag if you want a quiet lab.

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

- Host defaults to `127.0.0.1`.
