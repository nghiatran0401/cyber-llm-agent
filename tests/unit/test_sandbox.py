"""Tests for OWASP sandbox event generation."""

import json
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest

from src.sandbox.owasp_sandbox import (
    list_scenarios,
    generate_event,
    append_event_to_live_log,
    event_to_analysis_text,
)


def test_list_scenarios_contains_three_core_cases():
    scenarios = list_scenarios()
    assert "sqli" in scenarios
    assert "xss" in scenarios
    assert "bruteforce" in scenarios


def test_generate_event_has_required_fields():
    event = generate_event("sqli", vulnerable_mode=True, source_ip="10.0.0.5")
    for key in (
        "timestamp",
        "scenario_id",
        "source_ip",
        "endpoint",
        "payload_pattern",
        "status_code",
        "risk_hint",
        "raw_event",
        "mode",
    ):
        assert key in event
    assert event["status_code"] == 401
    assert event["mode"] == "vulnerable"


def test_append_event_writes_jsonl(tmp_path):
    event = generate_event("xss", vulnerable_mode=False)
    output_path = tmp_path / "live_web_logs.jsonl"
    append_event_to_live_log(event, output_path=output_path)
    assert output_path.exists()
    loaded = json.loads(output_path.read_text(encoding="utf-8").strip())
    assert loaded["scenario_id"] == event["scenario_id"]


def test_event_to_analysis_text_contains_risk_hint():
    event = generate_event("bruteforce", vulnerable_mode=True)
    text = event_to_analysis_text(event)
    assert "risk_hint" in text
    assert "BrokenAuth" in text


# ── New unhappy-path tests ─────────────────────────────────────────────────────

def test_generate_event_unknown_scenario():
    """Unknown scenario raises ValueError."""
    with pytest.raises(ValueError, match="Unknown scenario"):
        generate_event("unknown_attack", vulnerable_mode=True)


def test_append_event_io_failure(tmp_path):
    """OSError during file write propagates."""
    event = generate_event("sqli", vulnerable_mode=True)
    with patch("builtins.open", side_effect=OSError("disk full")):
        with pytest.raises(OSError):
            append_event_to_live_log(event, output_path=tmp_path / "fail.jsonl")


def test_generate_event_safe_mode_status_codes():
    """Safe mode produces status 200, vulnerable mode produces 401."""
    for scenario in ["sqli", "xss", "bruteforce"]:
        safe = generate_event(scenario, vulnerable_mode=False)
        vuln = generate_event(scenario, vulnerable_mode=True)
        assert safe["status_code"] == 200, f"{scenario} safe mode should be 200"
        assert vuln["status_code"] == 401, f"{scenario} vulnerable mode should be 401"
        assert safe["mode"] == "safe"
        assert vuln["mode"] == "vulnerable"


def test_append_event_concurrent_writes(tmp_path):
    """Concurrent writes produce valid JSONL without corruption."""
    output_path = tmp_path / "concurrent.jsonl"
    events = [generate_event("sqli", vulnerable_mode=True, source_ip=f"10.0.0.{i}") for i in range(50)]

    def write_event(event):
        append_event_to_live_log(event, output_path=output_path)

    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(write_event, events))

    lines = output_path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 50
    for line in lines:
        parsed = json.loads(line)
        assert "scenario_id" in parsed


# ── Lab compatibility tests ────────────────────────────────────────────────────

def test_sandbox_event_matches_analyze_request():
    """Generated event can be used as SandboxAnalyzeRequest event payload."""
    from services.api.schemas import SandboxAnalyzeRequest
    event = generate_event("sqli", vulnerable_mode=True)
    req = SandboxAnalyzeRequest(event=event, mode="g1")
    assert req.event["scenario_id"] == "owasp_sqli_001"


def test_all_scenarios_produce_valid_events():
    """All 3 scenarios produce events valid for SandboxAnalyzeRequest."""
    from services.api.schemas import SandboxAnalyzeRequest
    for scenario in list_scenarios():
        event = generate_event(scenario, vulnerable_mode=True)
        req = SandboxAnalyzeRequest(event=event, mode="g1")
        assert req.event["risk_hint"]


def test_oversized_event_rejected():
    """Event with >32 keys is rejected by SandboxAnalyzeRequest validator."""
    from services.api.schemas import SandboxAnalyzeRequest
    event = {f"key_{i}": f"value_{i}" for i in range(33)}
    with pytest.raises(Exception):
        SandboxAnalyzeRequest(event=event, mode="g1")
