"""Shared ReAct runtime helpers for trace shape and stop-reason control."""

from __future__ import annotations

from typing import Optional

from .schemas import StepTrace

STOP_REASON_PRIORITY = {
    "completed": 1,
    "budget_exceeded": 2,
    "blocked": 3,
    "needs_human": 4,
    "error": 5,
}


def normalize_stop_reason(reason: Optional[str], default: str = "completed") -> str:
    """Normalize unknown stop reasons to a known value."""
    candidate = str(reason or "").strip()
    if candidate in STOP_REASON_PRIORITY:
        return candidate
    return default


def resolve_stop_reason(*reasons: Optional[str], default: str = "completed") -> str:
    """Resolve one deterministic stop reason by priority."""
    resolved = normalize_stop_reason(default, default=default)
    best_priority = STOP_REASON_PRIORITY.get(resolved, 0)
    for reason in reasons:
        normalized = normalize_stop_reason(reason, default=default)
        priority = STOP_REASON_PRIORITY.get(normalized, 0)
        if priority > best_priority:
            resolved = normalized
            best_priority = priority
    return resolved


def build_step_trace(
    *,
    step: str,
    what_it_does: str,
    prompt_preview: str = "",
    input_summary: str = "",
    output_summary: str = "",
    run_id: Optional[str] = None,
    step_id: Optional[str] = None,
    tool_call_id: Optional[str] = None,
) -> StepTrace:
    """Create StepTrace with required fields always populated."""
    return StepTrace(
        step=(step or "Unknown").strip() or "Unknown",
        what_it_does=(what_it_does or "").strip() or "n/a",
        prompt_preview=str(prompt_preview or ""),
        input_summary=str(input_summary or ""),
        output_summary=str(output_summary or ""),
        run_id=run_id,
        step_id=step_id,
        tool_call_id=tool_call_id,
    )
