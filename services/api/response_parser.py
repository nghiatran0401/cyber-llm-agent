"""Response parsing and structured report building for API results."""

from __future__ import annotations

import re
from typing import Any, Dict, List

_SEVERITY_ORDER = ("critical", "high", "medium", "low")


def summarize_text(text: str, max_len: int = 220) -> str:
    """Collapse text to a short human-readable preview."""
    content = (text or "").strip().replace("\n", " ")
    if len(content) <= max_len:
        return content
    return content[:max_len] + "..."


def extract_bullets(section_name: str, text: str) -> List[str]:
    """Extract bulleted items from a named section of text."""
    pattern = re.compile(rf"{re.escape(section_name)}\s*:?\s*(.*?)(?:\n\s*\n|$)", re.IGNORECASE | re.DOTALL)
    match = pattern.search(text or "")
    if not match:
        return []
    block = match.group(1)
    bullets = []
    for line in block.splitlines():
        stripped = line.strip()
        if stripped.startswith(("- ", "* ")):
            bullets.append(stripped[2:].strip())
    return [b for b in bullets if b]


def infer_severity(response_text: str) -> str:
    """Infer the severity level from the response text."""
    lower = (response_text or "").lower()
    for severity in _SEVERITY_ORDER:
        if severity in lower:
            return severity
    return "unknown"


def extract_citations(response_text: str) -> List[str]:
    """Extract deduplicated citation lines from a response."""
    citations: List[str] = []
    for raw_line in (response_text or "").splitlines():
        line = raw_line.strip()
        if line.lower().startswith("source:"):
            citations.append(line)
        elif "#chunk-" in line:
            citations.append(line.lstrip("- ").strip())
    deduped: List[str] = []
    for c in citations:
        if c not in deduped:
            deduped.append(c)
    return deduped


def build_structured_g1_report(response_text: str) -> Dict[str, Any]:
    """Parse model output into a structured G1 security report."""
    findings = extract_bullets("findings", response_text)
    actions = extract_bullets("recommended actions", response_text) or extract_bullets(
        "recommended action", response_text
    )
    if not findings:
        findings = [summarize_text(response_text, 320)]
    confidence = "low"
    lower = (response_text or "").lower()
    if "confidence: high" in lower:
        confidence = "high"
    elif "confidence: medium" in lower:
        confidence = "medium"
    return {
        "severity": infer_severity(response_text),
        "findings": findings,
        "recommended_actions": actions,
        "confidence": confidence,
        "citations": extract_citations(response_text),
    }


def critic_validate_structured_output(structured: Dict[str, Any], high_risk: bool) -> tuple[bool, str]:
    """Critic check: validate that structured output meets evidence requirements."""
    findings = structured.get("findings") or []
    actions = structured.get("recommended_actions") or []
    citations = structured.get("citations") or []
    if not findings:
        return False, "Missing findings in structured output."
    if high_risk and not actions:
        return False, "High-risk response missing recommended actions."
    if high_risk and not citations:
        return False, "High-risk response missing evidence citations."
    return True, "Structured output passed critic checks."


def extract_response_text(result: Any) -> str:
    """Normalize agent result into plain text."""
    if isinstance(result, dict):
        if "output" in result:
            return str(result["output"])
        if "messages" in result and result["messages"]:
            last = result["messages"][-1]
            if hasattr(last, "content"):
                return str(last.content)
            if isinstance(last, tuple) and len(last) == 2:
                return str(last[1])
            return str(last)
    if hasattr(result, "content"):
        return str(result.content)
    return str(result)
