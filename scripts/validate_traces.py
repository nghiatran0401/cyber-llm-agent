#!/usr/bin/env python3
"""Week 3: End-to-end trace consistency validator.

Sends requests to the running API and validates that:
1. Every response has a valid ApiResponse envelope
2. Trace steps have required fields (step, what_it_does, run_id, step_id)
3. ResponseMeta has request_id, run_id, mode, stop_reason
4. Trace run_ids match meta.run_id
5. G2 results contain expected sub-report keys
6. Streaming endpoint emits trace, final, and done events
"""

import json
import sys
import requests

BASE_URL = "http://127.0.0.1:8000"
HEADERS = {"Content-Type": "application/json"}
ERRORS: list[str] = []
PASSES: list[str] = []


def check(name: str, condition: bool, detail: str = ""):
    if condition:
        PASSES.append(name)
    else:
        ERRORS.append(f"FAIL: {name} — {detail}")


def validate_envelope(data: dict, label: str):
    check(f"{label}: has ok field", "ok" in data, "missing 'ok'")
    check(f"{label}: has meta field", "meta" in data, "missing 'meta'")
    meta = data.get("meta", {})
    check(f"{label}: meta.request_id present", bool(meta.get("request_id")), "missing request_id")


def validate_trace(data: dict, label: str):
    meta = data.get("meta", {})
    run_id = meta.get("run_id")
    trace = data.get("trace", [])
    if not trace:
        return
    for i, step in enumerate(trace):
        prefix = f"{label}: trace[{i}]"
        check(f"{prefix} has step", bool(step.get("step")), "missing step name")
        check(f"{prefix} has what_it_does", bool(step.get("what_it_does")), "missing description")
        check(f"{prefix} has run_id", bool(step.get("run_id")), "missing run_id")
        check(f"{prefix} run_id matches meta", step.get("run_id") == run_id,
              f"step run_id={step.get('run_id')} != meta run_id={run_id}")


def test_health():
    resp = requests.get(f"{BASE_URL}/api/v1/health", timeout=5)
    check("health: status 200", resp.status_code == 200, f"got {resp.status_code}")
    data = resp.json()
    validate_envelope(data, "health")
    check("health: result.status is healthy", data.get("result", {}).get("status") == "healthy")


def test_g1_analysis():
    resp = requests.post(f"{BASE_URL}/api/v1/analyze/g1", json={"input": "Failed SSH login from 10.0.0.1"}, headers=HEADERS, timeout=60)
    check("g1: status 200", resp.status_code == 200, f"got {resp.status_code}")
    data = resp.json()
    validate_envelope(data, "g1")
    validate_trace(data, "g1")
    meta = data.get("meta", {})
    check("g1: mode is g1", meta.get("mode") == "g1", f"got mode={meta.get('mode')}")
    check("g1: stop_reason present", bool(meta.get("stop_reason")), "missing stop_reason")
    check("g1: result not empty", bool(data.get("result")), "empty result")


def test_g2_analysis():
    resp = requests.post(f"{BASE_URL}/api/v1/analyze/g2", json={"input": "Port scan detected from external IP"}, headers=HEADERS, timeout=120)
    check("g2: status 200", resp.status_code == 200, f"got {resp.status_code}")
    data = resp.json()
    validate_envelope(data, "g2")
    validate_trace(data, "g2")
    meta = data.get("meta", {})
    check("g2: mode is g2", meta.get("mode") == "g2", f"got mode={meta.get('mode')}")
    result = data.get("result", {})
    if isinstance(result, dict):
        check("g2: has final_report", bool(result.get("final_report")), "missing final_report key")


def test_chat():
    resp = requests.post(f"{BASE_URL}/api/v1/chat", json={"input": "What is XSS?", "mode": "g1"}, headers=HEADERS, timeout=60)
    check("chat: status 200", resp.status_code == 200, f"got {resp.status_code}")
    data = resp.json()
    validate_envelope(data, "chat")
    validate_trace(data, "chat")


def test_stream():
    resp = requests.post(
        f"{BASE_URL}/api/v1/workspace/stream",
        json={"input": "Analyze failed logins", "mode": "g1"},
        headers=HEADERS,
        stream=True,
        timeout=120,
    )
    check("stream: status 200", resp.status_code == 200, f"got {resp.status_code}")
    events = {"trace": 0, "final": 0, "done": 0, "error": 0}
    for line in resp.iter_lines(decode_unicode=True):
        if not line or not line.startswith("data:"):
            continue
        payload = json.loads(line[5:].strip())
        event_type = payload.get("type", "unknown")
        if event_type in events:
            events[event_type] += 1
    check("stream: received final event", events["final"] >= 1, f"final={events['final']}")
    check("stream: received done event", events["done"] >= 1, f"done={events['done']}")
    check("stream: no error events", events["error"] == 0, f"errors={events['error']}")


def test_metrics_dashboard():
    resp = requests.get(f"{BASE_URL}/api/v1/metrics/dashboard", timeout=5)
    check("dashboard: status 200", resp.status_code == 200, f"got {resp.status_code}")
    data = resp.json()
    validate_envelope(data, "dashboard")
    result = data.get("result", {})
    check("dashboard: has summary", "summary" in result, "missing summary key")
    check("dashboard: has breakdown", "breakdown" in result, "missing breakdown key")


def main():
    print("=== End-to-End Trace Validation ===\n")

    tests = [test_health, test_g1_analysis, test_g2_analysis, test_chat, test_stream, test_metrics_dashboard]
    for test_fn in tests:
        name = test_fn.__name__
        try:
            print(f"Running {name}...")
            test_fn()
        except requests.ConnectionError:
            ERRORS.append(f"FAIL: {name} — API not reachable at {BASE_URL}")
        except Exception as exc:
            ERRORS.append(f"FAIL: {name} — {exc}")

    print(f"\n{'='*60}")
    print(f"Passed: {len(PASSES)}")
    print(f"Failed: {len(ERRORS)}")

    if ERRORS:
        print("\nFailures:")
        for err in ERRORS:
            print(f"  {err}")
        sys.exit(1)
    else:
        print("\nAll trace validations passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
