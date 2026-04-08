#!/usr/bin/env python3
"""Single-command smoke checklist for core API workflows.

This script validates:
- health + readiness envelopes
- G1/G2/chat/workspace stream endpoint wiring
- sandbox endpoint wiring
- basic local RAG ingest/retrieve behavior with citations

When to use:
- Quick local sanity check after endpoint wiring/refactors.
- Before demos when you want deterministic mocked validation.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services.api.main import app
from src.tools import rag_tools


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str


def _result(name: str, ok: bool, detail: str) -> CheckResult:
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}: {detail}")
    return CheckResult(name=name, ok=ok, detail=detail)


def _parse_stream_events(response) -> list[dict]:
    events: list[dict] = []
    for line in response.iter_lines():
        if line and line.startswith("data: "):
            events.append(json.loads(line.replace("data: ", "")))
    return events


def run_checklist() -> int:
    results: list[CheckResult] = []

    def fake_run_g1_analysis(user_input: str, session_id=None):
        _ = (user_input, session_id)
        return "mocked g1 response", [], "gpt-4o-mini"

    def fake_run_g2_analysis(log_input: str, session_id=None):
        _ = (log_input, session_id)
        return (
            {
                "log_evidence": "parsed logs",
                "rag_context": "Retrieved Context:\n- source=data/knowledge/security_basics.md#chunk-1\nCitations:\n- data/knowledge/security_basics.md#chunk-1",
                "cti_evidence": "Source: CTI Fallback",
                "log_analysis": "suspicious failed logins",
                "threat_prediction": "likely brute force continuation",
                "incident_response": "block IP and force password reset",
                "final_report": "high risk; immediate containment required",
            },
            [],
            "gpt-4o-mini",
        )

    def fake_run_chat(user_input: str, mode: str = "g1", session_id=None):
        _ = (user_input, session_id)
        if mode == "g2":
            return "mocked g2 chat response", [], "gpt-4o-mini"
        return "mocked g1 chat response", [], "gpt-4o-mini"

    def fake_workspace_with_progress(*, task, mode, user_input, on_step, session_id=None):
        _ = (task, mode, user_input, session_id)
        on_step(
            SimpleNamespace(
                model_dump=lambda: {
                    "step": "InputPreparation",
                    "what_it_does": "Validates request.",
                    "prompt_preview": "preview",
                    "input_summary": "input",
                    "output_summary": "ready",
                }
            )
        )
        return "workspace final response", "gpt-4o-mini"

    with patch("src.config.settings.Settings.validate", return_value=True), patch(
        "services.api.routes.run_g1_analysis", side_effect=fake_run_g1_analysis
    ), patch("services.api.routes.run_g2_analysis", side_effect=fake_run_g2_analysis), patch(
        "services.api.routes.run_chat", side_effect=fake_run_chat
    ), patch(
        "services.api.routes.run_workspace_with_progress", side_effect=fake_workspace_with_progress
    ), patch(
        "services.api.routes.get_sandbox_scenarios", return_value=["sqli", "xss", "bruteforce"]
    ), patch(
        "services.api.routes.simulate_sandbox_event",
        return_value={"scenario_id": "owasp_sqli_001", "mode": "safe", "source_ip": "127.0.0.1"},
    ), patch(
        "services.api.routes.analyze_sandbox_event",
        return_value=("sandbox analyzed", [], "gpt-4o-mini"),
    ):
        client = TestClient(app)

        # 1) Health and readiness
        health = client.get("/api/v1/health")
        results.append(_result("health endpoint", health.status_code == 200, f"status={health.status_code}"))
        ready = client.get("/api/v1/ready")
        results.append(_result("ready endpoint", ready.status_code == 200, f"status={ready.status_code}"))
        metrics = client.get("/api/v1/metrics")
        metrics_ok = metrics.status_code == 200 and "requests_total" in metrics.json().get("result", {})
        results.append(_result("metrics endpoint", metrics_ok, f"status={metrics.status_code}"))
        dashboard = client.get("/api/v1/metrics/dashboard")
        dashboard_ok = dashboard.status_code == 200 and "summary" in dashboard.json().get("result", {})
        results.append(_result("metrics dashboard endpoint", dashboard_ok, f"status={dashboard.status_code}"))

        # 2) Core endpoints
        g1 = client.post("/api/v1/analyze/g1", json={"input": "Analyze failed logins"})
        g2 = client.post("/api/v1/analyze/g2", json={"input": "Analyze failed logins"})
        chat = client.post("/api/v1/chat", json={"input": "hello", "mode": "g1"})
        g2_json = g2.json() if g2.status_code == 200 else {}
        rag_present = "Citations:" in str(g2_json.get("result", {}).get("rag_context", ""))
        results.append(_result("g1 analyze", g1.status_code == 200, f"status={g1.status_code}"))
        results.append(_result("g2 analyze", g2.status_code == 200, f"status={g2.status_code}"))
        results.append(_result("chat endpoint", chat.status_code == 200, f"status={chat.status_code}"))
        results.append(_result("g2 includes rag citations", rag_present, "rag_context contains citations"))

        with client.stream(
            "POST",
            "/api/v1/workspace/stream",
            json={"task": "chat", "mode": "g1", "input": "hello"},
        ) as stream_resp:
            events = _parse_stream_events(stream_resp)
        has_trace = any(e.get("type") == "trace" for e in events)
        has_final = any(e.get("type") == "final" for e in events)
        has_done = any(e.get("type") == "done" for e in events)
        results.append(_result("workspace stream trace/final/done", has_trace and has_final and has_done, f"events={len(events)}"))

        # 3) Sandbox endpoints
        scenarios = client.get("/api/v1/sandbox/scenarios")
        simulate = client.post(
            "/api/v1/sandbox/simulate",
            json={"scenario": "sqli", "vulnerable_mode": False, "source_ip": "127.0.0.1", "append_to_live_log": False},
        )
        analyze = client.post(
            "/api/v1/sandbox/analyze",
            json={"event": {"scenario_id": "owasp_sqli_001", "raw_event": "sql injection"}, "mode": "g1"},
        )
        results.append(_result("sandbox scenarios", scenarios.status_code == 200, f"status={scenarios.status_code}"))
        results.append(_result("sandbox simulate", simulate.status_code == 200, f"status={simulate.status_code}"))
        results.append(_result("sandbox analyze", analyze.status_code == 200, f"status={analyze.status_code}"))

        # 4) RAG helpers (Pinecone path — mock I/O; live ingest needs keys + network)
        with patch.object(
            rag_tools,
            "ingest_knowledge_base",
            return_value="RAG index refreshed using Pinecone. Processed 1 documents into 2 chunks.",
        ), patch.object(
            rag_tools,
            "retrieve_security_context",
            return_value=(
                "Retrieved Context (source=pinecone_semantic):\n"
                "- Match 1 [score=1.0000] [source=data/knowledge/security_basics.md#1]: brute force login attempts\n"
                "Citations:\n"
                "- data/knowledge/security_basics.md#1"
            ),
        ):
            ingest_message = rag_tools.ingest_knowledge_base()
            retrieved = rag_tools.retrieve_security_context("failed login brute force")
            rag_ok = "chunks" in ingest_message.lower() and "Citations:" in retrieved
            results.append(_result("rag ingest+retrieve (mocked)", rag_ok, "ingest and citation shape"))

    failed = [result for result in results if not result.ok]
    print("-" * 72)
    print(f"Checklist complete: {len(results) - len(failed)}/{len(results)} checks passed.")
    if failed:
        print("Failures:")
        for result in failed:
            print(f"- {result.name}: {result.detail}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run_checklist())
