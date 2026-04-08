"""G2 input preflight: off-topic refusal and incident-evidence expectations.

G2 is built for evidence-bearing defensive analysis. These checks avoid running the
full multi-agent pipeline on trivia or on bare follow-ups with no session context.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from src.utils.session_manager import SessionManager

# Signals that the message (or merged session context) plausibly describes a security incident or technical evidence.
_INCIDENT_EVIDENCE_RE = re.compile(
    r"(cloudtrail|cloudwatch|guardduty|iam\b|aws\b|assumedrole|createaccesskey|"
    r"getobject|listbucket|exfil|compromise|breach|\bincident\b|forensic|malware|ransomware|ioc\b|"
    r"trojan|cve-\d{4}|phish|bypass|credential\s*(abuse|theft|misuse)|credential\s+stuffing|password\s+spray|"
    r"authentication|\bauth\b|endpoint\b|traffic\b|unauthorized\s+access|suspicious\s+activ|threat\s+hunt|"
    r"siem|splunk|crowdstrike|sentinel|edr\b|vpn\b|firewall|proxy\b|waf\b|"
    r"\blog\s*analysis|eventname|requestid|finding_id|detection\b|"
    r"event=|\blog\b\(|4624|4625|4688|"
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|"
    r"\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2})",
    re.IGNORECASE,
)

# Trivia / chit-chat that should not invoke the incident pipeline (when no incident cues appear).
_OFF_TOPIC_HINTS = re.compile(
    r"(?:^|\n)\s*(who\s+is|who'|what\s+is\s+the\s+capital|"
    r"recipe\s+for|nba\s|nfl\s|super\s+bowl|oscar|grammy|"
    r"taylor\s+swift|beyonc[eé]|michael\s+jackson|elvis\s)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class G2PreflightResult:
    """Result of evaluating whether to run the G2 graph."""

    ok: bool
    stop_reason: str  # "completed" | "needs_human"
    final_report: str


def message_has_incident_cues(text: str) -> bool:
    """Return True if text looks like incident logs, cloud telemetry, or defensive analysis context."""
    return bool(text and _INCIDENT_EVIDENCE_RE.search(text))


def _looks_off_topic_non_security(text: str) -> bool:
    """Heuristic: clearly not a security/analysis request."""
    t = (text or "").strip()
    if not t:
        return True
    if message_has_incident_cues(t):
        return False
    if _OFF_TOPIC_HINTS.search(t):
        return True
    # Very short conversational opener with no security substance
    if len(t) < 24 and not re.search(r"\b(security|soc|incident|aws|log|alert|threat)\b", t, re.I):
        if t.lower().rstrip("?") in {"hi", "hello", "hey", "thanks", "thank you", "ok", "okay"}:
            return True
    return False


def preflight_g2_user_turn(*, current_message: str) -> Optional[G2PreflightResult]:
    """Evaluate only the latest user message. Returns a terminal result or None to continue."""
    if _looks_off_topic_non_security(current_message):
        return G2PreflightResult(
            ok=False,
            stop_reason="needs_human",
            final_report=(
                "I only handle defensive security and incident-analysis questions here. "
                "Ask about logs, alerts, AWS/GCP/Azure telemetry, or threat-hunting steps."
            ),
        )
    return None


def preflight_g2_evidence_bundle(*, bundle_text: str) -> Optional[G2PreflightResult]:
    """Ensure combined transcript has enough incident substance for G2."""
    if message_has_incident_cues(bundle_text):
        return None
    return G2PreflightResult(
        ok=False,
        stop_reason="needs_human",
        final_report=(
            "This mode needs concrete incident evidence (log lines, alert text, resource IDs, timestamps, or IPs) "
            "or a clear defensive-security analysis question. Paste the artifacts again in the same message, "
            "or continue in G1 chat so prior turns stay in memory."
        ),
    )


def _session_messages(session_id: str) -> list[dict]:
    try:
        data = SessionManager().load_session(session_id)
    except ValueError:
        return []
    raw = data.get("messages")
    return raw if isinstance(raw, list) else []


def compose_g2_input_with_session(session_id: Optional[str], current_user_message: str) -> str:
    """Attach prior **user** turns only so follow-ups keep pasted evidence without re-ingesting assistant prose as logs.

    Prior assistant replies must not be merged into the bundle: the G2 log analyzer treats the whole blob as
    telemetry, which caused follow-ups to derail (model \"re-analyzing\" its own narrative).
    """
    current_user_message = (current_user_message or "").strip()
    if not session_id or not str(session_id).strip():
        return current_user_message
    msgs = _session_messages(str(session_id).strip())
    if not msgs:
        return current_user_message
    user_turns: list[str] = []
    for m in msgs:
        if not isinstance(m, dict):
            continue
        if str(m.get("role", "")).strip() != "user":
            continue
        content = str(m.get("content", "")).strip()
        if content:
            user_turns.append(content)
    if not user_turns:
        return current_user_message
    # Keep the most recent user questions/evidence (follow-up chains); cap size from the end.
    history = "\n\n---\n\n".join(user_turns[-5:])
    max_hist = 14_000
    if len(history) > max_hist:
        history = history[-max_hist:]
    return (
        "Prior messages below are only **user** questions and any log/telemetry they pasted. "
        "Do not treat missing assistant text as a gap—answer the **Current request** using that evidence.\n\n"
        f"### Prior user turns\n{history}\n\n"
        f"### Current request\n{current_user_message}"
    )


def persist_g2_turn(*, session_id: Optional[str], user_message: str, assistant_report: str) -> None:
    """Append this exchange to the workspace session (same shape as G1 memory messages)."""
    if not session_id or not str(session_id).strip():
        return
    sid = str(session_id).strip()
    try:
        sm = SessionManager()
        data = sm.load_session(sid)
    except ValueError:
        return
    messages: list[dict] = list(data.get("messages") or []) if isinstance(data.get("messages"), list) else []
    messages.append({"role": "user", "content": (user_message or "").strip()})
    messages.append({"role": "assistant", "content": (assistant_report or "").strip()})
    data["messages"] = messages[-48:]
    sm.save_session(sid, data)
