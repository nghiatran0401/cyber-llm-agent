"""Input/output security guardrails for the API service layer."""

from __future__ import annotations

from src.config.settings import Settings

MAX_INPUT_CHARS = 50_000
MAX_EVENT_TEXT_CHARS = 10_000
MAX_EVENT_KEYS = 32

_PROMPT_INJECTION_MARKERS = (
    "ignore previous instructions",
    "ignore all prior",
    "system prompt",
    "developer message",
    "reveal hidden instructions",
    "bypass policy",
    "disable guardrails",
)
_OUTPUT_POLICY_DENYLIST = (
    "BEGIN PRIVATE KEY",
    "OPENAI_API_KEY=",
    "authorization: bearer ",
    "how to weaponize",
    "drop table users",
)


def validate_input(text: str, input_name: str = "input") -> str:
    """Validate and return a cleaned input string."""
    value = (text or "").strip()
    if not value:
        raise ValueError(f"{input_name} is empty.")
    if len(value) > MAX_INPUT_CHARS:
        raise ValueError(
            f"{input_name} is too large ({len(value)} chars). "
            f"Please keep it under {MAX_INPUT_CHARS} characters."
        )
    return value


def sanitize_untrusted_text(text: str) -> str:
    """Strip non-printable control chars and normalize whitespace."""
    sanitized = "".join(ch for ch in str(text or "") if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    return sanitized.replace("\x00", "").strip()


def enforce_response_boundaries(text: str, max_chars: int = 12000) -> str:
    """Trim response text to stay within output boundaries."""
    content = str(text or "").replace("\x00", "").strip()
    if len(content) <= max_chars:
        return content
    return content[: max_chars - 3].rstrip() + "..."


def detect_prompt_injection(text: str) -> bool:
    """Return True if the text contains prompt-injection markers."""
    content = (text or "").lower()
    return any(marker in content for marker in _PROMPT_INJECTION_MARKERS)


def apply_output_policy_guard(text: str) -> tuple[bool, str]:
    """Check output against the policy denylist. Returns (allowed, status)."""
    if not Settings.ENABLE_OUTPUT_POLICY_GUARD:
        return True, "disabled"
    content = text or ""
    for blocked in _OUTPUT_POLICY_DENYLIST:
        if blocked.lower() in content.lower():
            return False, f"blocked_content:{blocked}"
    return True, "pass"


def apply_action_gating(
    response: str,
    *,
    high_risk: bool,
    evidence_count: int,
) -> tuple[str, str]:
    """Apply safety gates for high-risk responses. Returns (response, stop_reason)."""
    if not high_risk:
        return response, "completed"

    if evidence_count < Settings.MIN_EVIDENCE_FOR_HIGH_RISK:
        gated = (
            f"{response}\n\nSafety gate: high-risk recommendation lacks required evidence "
            f"(minimum={Settings.MIN_EVIDENCE_FOR_HIGH_RISK}, observed={evidence_count})."
        )
        return enforce_response_boundaries(gated), "needs_human"

    if Settings.REQUIRE_HUMAN_APPROVAL_HIGH_RISK:
        gated = (
            f"{response}\n\nSafety gate: high-risk actions require explicit human approval before execution."
        )
        return enforce_response_boundaries(gated), "needs_human"

    return response, "completed"


def validate_event_payload(event: dict) -> dict:
    """Validate a sandbox event dict for size and structure."""
    if not isinstance(event, dict):
        raise ValueError("event must be an object.")
    if len(event) > MAX_EVENT_KEYS:
        raise ValueError(f"event has too many keys (max={MAX_EVENT_KEYS}).")
    serialized = validate_input(str(event), "event")
    if len(serialized) > MAX_EVENT_TEXT_CHARS:
        raise ValueError(f"event is too large. Keep under {MAX_EVENT_TEXT_CHARS} characters.")
    return event


def count_evidence_markers(text: str) -> int:
    """Count evidence citation markers in a text string."""
    content = (text or "").lower()
    return sum([
        content.count("source:"),
        content.count("#chunk-"),
        content.count("citation"),
        content.count("cti"),
    ])
