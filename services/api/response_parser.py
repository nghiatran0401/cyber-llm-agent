"""Response parsing and structured report building for API results."""

from __future__ import annotations

import re
from typing import Any, Dict, List

_SEVERITY_ORDER = ("critical", "high", "medium", "low")

# Major SOC-style headings used to slice sections (order not significant).
_MAJOR_HEADINGS = (
    "Indicators",
    "Threat assessment",
    "Recommended actions",
    "Findings",
    "Citations",
)


def _heading_family(name: str) -> str:
    n = (name or "").strip().lower()
    if n.startswith("recommended action"):
        return "recommended"
    if n in ("indicators", "findings"):
        return "indicators"
    return n


def _extract_section_text(text: str, heading: str) -> str:
    """Return body text after ``Heading:`` until another major section or ``Source:``."""
    if not text or not heading:
        return ""
    esc = re.escape(heading.strip())
    m = re.search(rf"(?im)^\s*{esc}\s*:\s*", text)
    if not m:
        return ""
    tail = text[m.end() :].lstrip("\n\r")
    fam = _heading_family(heading)
    others = [h for h in _MAJOR_HEADINGS if _heading_family(h) != fam]
    alt = "|".join(re.escape(o) for o in others)
    stop = re.compile(rf"(?im)^\s*(?:{alt})\s*:\s*")
    sm = stop.search(tail)
    if sm:
        tail = tail[: sm.start()]
    src = re.search(r"(?im)^Source:\s*", tail)
    if src:
        tail = tail[: src.start()]
    return tail.rstrip()


def _is_subsection_title_line(s: str) -> bool:
    s = s.strip()
    if not s.endswith(":") or len(s) > 80:
        return False
    body = s[:-1].strip()
    return bool(body) and len(body) < 60


def _lines_as_items(block: str) -> List[str]:
    """Pull list items from a section: bullets, numbered lines, or substantive paragraphs."""
    items: List[str] = []
    for line in (block or "").splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith(("- ", "* ")):
            items.append(s[2:].strip())
            continue
        if re.match(r"^\d+\.\s+", s):
            items.append(re.sub(r"^\d+\.\s+", "", s).strip())
            continue
        if _is_subsection_title_line(s):
            continue
        if len(s) >= 12:
            items.append(s)
    return [b for b in items if b]


def summarize_text(text: str, max_len: int = 220) -> str:
    """Collapse text to a short human-readable preview."""
    content = (text or "").strip().replace("\n", " ")
    if len(content) <= max_len:
        return content
    return content[:max_len] + "..."


def extract_bullets(section_name: str, text: str) -> List[str]:
    """Extract items from a named section (bullets, numbered steps, or paragraph lines).

    Uses heading-based slicing so a blank line after ``Recommended actions:`` does not
    truncate the section (previous regex stopped at the first ``\\n\\n``).
    """
    raw = text or ""
    aliases: tuple[str, ...]
    sl = section_name.strip().lower()
    if sl == "findings":
        aliases = ("Findings", "Indicators")
    elif sl.startswith("recommended action"):
        aliases = ("Recommended actions", "Recommended action")
    else:
        aliases = (section_name.strip().title() if section_name.islower() else section_name,)

    block = ""
    for h in aliases:
        block = _extract_section_text(raw, h)
        if block:
            break
    if not block:
        return []

    bullets: List[str] = []
    for line in block.splitlines():
        stripped = line.strip()
        if stripped.startswith(("- ", "* ")):
            bullets.append(stripped[2:].strip())
    if bullets:
        return [b for b in bullets if b]
    return _lines_as_items(block)


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
    actions = extract_bullets("recommended actions", response_text)
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


def _is_memory_recall_query(user_text: str) -> bool:
    t = (user_text or "").lower()
    return any(
        p in t
        for p in (
            "do you remember",
            "did you remember",
            "remember from",
            "last conversation",
            "our last conversation",
            "did we discuss",
            "recall what",
            "you recall",
        )
    )


def _is_procedural_how_to_query(user_text: str) -> bool:
    t = (user_text or "").lower()
    return any(
        p in t
        for p in (
            "how to ",
            "how do i ",
            "how can i ",
            "how should i ",
            "walk me through",
            "steps to ",
            "step by step",
        )
    )


def critic_validate_structured_output(
    structured: Dict[str, Any],
    high_risk: bool,
    user_text: str = "",
) -> tuple[bool, str]:
    """Critic check: validate that structured output meets evidence requirements."""
    findings = structured.get("findings") or []
    actions = structured.get("recommended_actions") or []
    citations = structured.get("citations") or []
    relaxed = _is_memory_recall_query(user_text) or _is_procedural_how_to_query(user_text)

    if not findings:
        return False, "Missing findings in structured output."
    if high_risk and not actions:
        if _is_memory_recall_query(user_text):
            return True, "Structured output passed critic checks."
        return False, "High-risk response missing recommended actions."
    if high_risk and not citations:
        if relaxed:
            return True, "Structured output passed critic checks."
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
