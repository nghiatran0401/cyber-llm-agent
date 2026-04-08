"""Unit tests for G2 input preflight and session composition."""

from pathlib import Path

import pytest

from services.api.g2_input_gate import (
    compose_g2_input_with_session,
    message_has_incident_cues,
    persist_g2_turn,
    preflight_g2_evidence_bundle,
    preflight_g2_user_turn,
)
from src.config.settings import Settings
from src.utils.session_manager import SessionManager


def test_preflight_blocks_trivia_when_no_security_cues():
    blocked = preflight_g2_user_turn(current_message="Who is Michael Jackson?")
    assert blocked is not None
    assert blocked.ok is False


def test_preflight_allows_aws_incident_question():
    assert preflight_g2_user_turn(current_message="IAM keys created on legacy users; GuardDuty finding gd-1") is None


def test_evidence_bundle_requires_substance():
    missing = preflight_g2_evidence_bundle(bundle_text="hello there")
    assert missing is not None
    assert "concrete incident evidence" in missing.final_report


def test_compose_g2_input_merges_session(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(Settings, "SESSIONS_DIR", tmp_path)
    sm = SessionManager(session_dir=tmp_path)
    sm.save_session(
        "sess-a",
        {
            "messages": [
                {"role": "user", "content": "CloudTrail CreateAccessKey on user X\n198.51.100.77"},
                {"role": "assistant", "content": "Revoke keys and scan S3."},
            ]
        },
    )
    merged = compose_g2_input_with_session("sess-a", "Give rollback-safe containment.")
    assert "CloudTrail" in merged
    assert "rollback-safe" in merged
    assert "Revoke keys" not in merged


def test_compose_never_includes_assistant_content(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(Settings, "SESSIONS_DIR", tmp_path)
    sm = SessionManager(session_dir=tmp_path)
    sm.save_session(
        "sess-b",
        {
            "messages": [
                {"role": "user", "content": "event=4625 ip=10.0.0.5"},
                {"role": "assistant", "content": "UNIQUE_ASSISTANT_MARKER_xyz123 elaborate summary"},
            ]
        },
    )
    merged = compose_g2_input_with_session("sess-b", "What next?")
    assert "UNIQUE_ASSISTANT_MARKER_xyz123" not in merged
    assert "4625" in merged


def test_persist_g2_turn_appends_messages(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(Settings, "SESSIONS_DIR", tmp_path)
    persist_g2_turn(session_id="s1", user_message="u", assistant_report="a")
    sm = SessionManager(session_dir=tmp_path)
    data = sm.load_session("s1")
    assert len(data.get("messages", [])) == 2


def test_message_has_incident_cues_detects_timestamps():
    assert message_has_incident_cues("2026-04-02T06:40:12Z cloudtrail event=CreateAccessKey")
