"""Local educational OWASP sandbox event generator."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from src.config.settings import Settings

SCENARIOS: Dict[str, Dict[str, str]] = {
    "sqli": {
        "scenario_id": "owasp_sqli_001",
        "endpoint": "/login",
        "payload_pattern": "' OR '1'='1",
        "risk_hint": "SQLi",
        "raw_event": "Suspicious SQL injection attack pattern detected in login input.",
    },
    "xss": {
        "scenario_id": "owasp_xss_001",
        "endpoint": "/search",
        "payload_pattern": "<script>alert(1)</script>",
        "risk_hint": "XSS",
        "raw_event": "Reflected XSS attack payload observed in query parameter.",
    },
    "bruteforce": {
        "scenario_id": "owasp_auth_001",
        "endpoint": "/auth/login",
        "payload_pattern": "multiple failed credentials",
        "risk_hint": "BrokenAuth",
        "raw_event": "Brute force attack behavior detected after repeated failed logins.",
    },
}


def list_scenarios() -> List[str]:
    """Return supported sandbox scenario keys."""
    return list(SCENARIOS.keys())


def generate_event(
    scenario_key: str,
    vulnerable_mode: bool,
    source_ip: str = "127.0.0.1",
) -> Dict[str, object]:
    """Generate one structured sandbox event."""
    if scenario_key not in SCENARIOS:
        raise ValueError(f"Unknown scenario '{scenario_key}'.")

    base = SCENARIOS[scenario_key]
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scenario_id": base["scenario_id"],
        "source_ip": source_ip,
        "endpoint": base["endpoint"],
        "payload_pattern": base["payload_pattern"],
        "status_code": 401 if vulnerable_mode else 200,
        "risk_hint": base["risk_hint"],
        "raw_event": base["raw_event"],
        "mode": "vulnerable" if vulnerable_mode else "safe",
    }


def append_event_to_live_log(event: Dict[str, object], output_path: Path | None = None) -> Path:
    """Append event as JSONL line into live web logs file."""
    path = output_path or (Settings.LOGS_DIR / "live_web_logs.jsonl")
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")
    return path


def event_to_analysis_text(event: Dict[str, object]) -> str:
    """Convert structured event into plain text for prompt-friendly analysis."""
    return (
        f"timestamp={event.get('timestamp')} "
        f"scenario_id={event.get('scenario_id')} "
        f"source_ip={event.get('source_ip')} "
        f"endpoint={event.get('endpoint')} "
        f"payload_pattern={event.get('payload_pattern')} "
        f"status_code={event.get('status_code')} "
        f"risk_hint={event.get('risk_hint')} "
        f"raw_event={event.get('raw_event')} "
        f"mode={event.get('mode')}"
    )

