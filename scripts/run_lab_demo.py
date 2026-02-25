"""Generate repeatable OWASP lab traffic and print CTI pipeline visibility.

Usage:
    python scripts/run_lab_demo.py --lab-base http://127.0.0.1:3100 --api-base http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass
from typing import Iterable
from urllib import parse, request


@dataclass
class DemoStep:
    method: str
    path: str
    data: dict[str, str] | None = None


def http_call(base_url: str, step: DemoStep) -> tuple[int, str]:
    url = f"{base_url.rstrip('/')}{step.path}"
    body = None
    headers = {}
    if step.data is not None:
        body = parse.urlencode(step.data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = request.Request(url=url, data=body, method=step.method.upper(), headers=headers)
    try:
        with request.urlopen(req, timeout=8) as response:
            payload = response.read().decode("utf-8", errors="replace")
            return response.status, payload[:160]
    except Exception as exc:  # pragma: no cover - runtime-only helper
        return 0, str(exc)


def http_get_json(url: str) -> dict:
    req = request.Request(url=url, method="GET")
    with request.urlopen(req, timeout=8) as response:
        return json.loads(response.read().decode("utf-8"))


def demo_steps() -> Iterable[DemoStep]:
    return [
        DemoStep("POST", "/lab/login", {"username": "admin", "password": "' OR '1'='1"}),
        DemoStep("GET", "/lab/search?q=%3Cscript%3Ealert(1)%3C/script%3E"),
        DemoStep("POST", "/lab/comment", {"message": "<img src=x onerror=alert(2)>"}),
        DemoStep("GET", "/lab/api/profile/1002?viewer=1001"),
        DemoStep("GET", "/lab/admin?role=user&debug=true"),
        DemoStep("GET", "/lab/download?file=../../.env"),
        DemoStep("POST", "/lab/import-config", {"payload": '{"__proto__":{"isAdmin":true}}'}),
    ]


def run_demo(lab_base: str, api_base: str, wait_seconds: float) -> None:
    print("== Running vulnerable lab traffic ==")
    for step in demo_steps():
        status, preview = http_call(lab_base, step)
        print(f"{step.method} {step.path} -> {status} | {preview}")
        time.sleep(0.25)

    print(f"\n== Waiting {wait_seconds:.1f}s for CTI bridge flush ==")
    time.sleep(wait_seconds)

    print("\n== Dashboard snapshots ==")
    events = http_get_json(f"{lab_base.rstrip('/')}/api/dashboard/events?limit=5")
    detections = http_get_json(f"{lab_base.rstrip('/')}/api/dashboard/detections?limit=5")
    stats = http_get_json(f"{lab_base.rstrip('/')}/api/dashboard/stats")
    print("events:")
    print(json.dumps(events.get("result", []), indent=2)[:1000])
    print("detections:")
    print(json.dumps(detections.get("result", []), indent=2)[:1000])
    print("stats:")
    print(json.dumps(stats.get("result", {}), indent=2))

    print("\n== FastAPI visibility endpoints ==")
    try:
        live_log = http_get_json(f"{api_base.rstrip('/')}/api/v1/sandbox/live-log?source=vuln_lab_events&tail=5")
        recent = http_get_json(f"{api_base.rstrip('/')}/api/v1/detections/recent?limit=5")
        mapping = http_get_json(f"{api_base.rstrip('/')}/api/v1/knowledge/owasp-mitre-map")
        print("live-log items:", len(live_log.get("result", {}).get("items", [])))
        print("recent detections:", recent.get("result", {}).get("count"))
        print("mapping keys:", sorted((mapping.get("result") or {}).keys()))
    except Exception as exc:  # pragma: no cover - runtime-only helper
        print(f"FastAPI visibility check failed: {exc}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run reproducible OWASP lab attack/demo flow.")
    parser.add_argument("--lab-base", default="http://127.0.0.1:3100")
    parser.add_argument("--api-base", default="http://127.0.0.1:8000")
    parser.add_argument("--wait-seconds", type=float, default=8.0)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_demo(lab_base=args.lab_base, api_base=args.api_base, wait_seconds=args.wait_seconds)
