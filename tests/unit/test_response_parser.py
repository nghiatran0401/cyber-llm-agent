"""Tests for G1 response parsing and critic rules."""

from services.api.response_parser import (
    build_structured_g1_report,
    critic_validate_structured_output,
    extract_bullets,
)
from services.api.guardrails import enforce_response_boundaries, strip_leaked_internal_prefixes


def test_extract_recommended_actions_after_blank_line():
    text = """Indicators: IP 1.2.3.4 seen.

Threat assessment: Suspicious.

Recommended actions:

Conduct a local log review.
Monitor for repeat attempts.

Citations:
- doc#1
"""
    actions = extract_bullets("recommended actions", text)
    assert len(actions) >= 2
    assert any("Conduct a local" in a for a in actions)
    assert any("Monitor" in a for a in actions)


def test_build_structured_includes_paragraph_actions():
    text = """Indicators: IP x

Threat assessment: Medium

Recommended actions:

Reset affected credentials.
Enable MFA on VPN.

"""
    structured = build_structured_g1_report(text)
    assert structured["recommended_actions"]
    assert any("MFA" in a for a in structured["recommended_actions"])


def test_critic_relaxes_citations_for_how_to():
    structured = {
        "severity": "high",
        "findings": ["See narrative"],
        "recommended_actions": ["Step one", "Step two"],
        "citations": [],
        "confidence": "low",
    }
    ok, msg = critic_validate_structured_output(
        structured, high_risk=True, user_text="How do I review firewall logs for this IP?"
    )
    assert ok is True
    assert "passed" in msg.lower()


def test_critic_relaxes_actions_for_memory_recall():
    structured = {
        "severity": "high",
        "findings": ["Yes, the prior turn mentioned IP 185.220.101.45."],
        "recommended_actions": [],
        "citations": [],
        "confidence": "low",
    }
    ok, msg = critic_validate_structured_output(
        structured, high_risk=True, user_text="Do you remember failed logins from last conversation?"
    )
    assert ok is True


def test_strip_leaked_conversation_prefix():
    raw = "Conversation / clarification: Hello! How can I help?"
    assert strip_leaked_internal_prefixes(raw) == "Hello! How can I help?"


def test_enforce_response_boundaries_strips_prefix():
    raw = "Conversation / clarification:\n\nHello there."
    assert enforce_response_boundaries(raw).startswith("Hello")
