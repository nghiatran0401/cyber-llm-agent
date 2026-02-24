"""Week 7 tests for OWASP sandbox event generation."""

import json

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

