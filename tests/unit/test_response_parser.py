"""Tests for G1 response parsing and critic heuristics."""

from services.api.response_parser import (
    build_structured_g1_report,
    critic_validate_structured_output,
    extract_bullets,
)


def test_extract_bullets_handles_bold_markdown_heading():
    text = (
        "**Indicators:**\n"
        "- OAuth consent phishing\n\n"
        "**Recommended Actions:**\n"
        "- Revoke application consent\n"
        "- Reset passwords\n"
    )
    actions = extract_bullets("recommended actions", text)
    assert actions == ["Revoke application consent", "Reset passwords"]


def test_extract_bullets_handles_hash_heading_and_subsection_paragraphs():
    text = (
        "### Recommended actions:\n\n"
        "Short-term:\n"
        "Isolate the affected mailbox and revoke risky OAuth grants.\n\n"
        "**Findings:**\n- Phishing link\n"
    )
    actions = extract_bullets("recommended actions", text)
    assert any("Isolate the affected mailbox" in a for a in actions)


def test_critic_high_risk_passes_when_user_message_has_incident_evidence():
    structured = build_structured_g1_report(
        "Severity: high\n"
        "Findings:\n- Suspicious login patterns\n\n"
        "Recommended actions:\n- Enforce MFA\n"
    )
    ok, _msg = critic_validate_structured_output(
        structured,
        high_risk=True,
        user_text="Review this AWS CloudTrail event: event=AssumeRole requestid=abc-123",
    )
    assert ok


def test_critic_high_risk_fails_citations_when_no_user_evidence_and_no_source():
    structured = build_structured_g1_report(
        "Severity: high\n"
        "Findings:\n- Unknown compromise\n\n"
        "Recommended actions:\n- Investigate\n"
    )
    ok, msg = critic_validate_structured_output(
        structured,
        high_risk=True,
        user_text="is this bad",
    )
    assert not ok
    assert "citations" in msg.lower()
