"""Shared ReAct runtime helpers for trace shape, loop budgets, and tool control."""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass, field
import time
from typing import Callable, Optional

from .schemas import StepTrace

STOP_REASON_PRIORITY = {
    "completed": 1,
    "budget_exceeded": 2,
    "blocked": 3,
    "needs_human": 4,
    "error": 5,
}

_NORMALIZED_WHITESPACE = " ".maketrans({"\n": " ", "\r": " ", "\t": " "})
_RUNTIME_BUDGET_STATE: ContextVar["RuntimeBudgetState | None"] = ContextVar(
    "react_runtime_budget_state",
    default=None,
)


@dataclass
class RuntimeBudgetState:
    """Track one execution's budgets, counters, and dedupe decisions."""

    max_steps: int
    max_tool_calls: int
    max_runtime_seconds: int
    started_at: float = field(default_factory=time.perf_counter)
    steps_used: int = 0
    tool_calls_used: int = 0
    duplicate_tool_calls: int = 0
    stop_reason: Optional[str] = None
    seen_tool_signatures: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class ToolCallDecision:
    """Describe whether a tool call should execute under the active runtime policy."""

    should_execute: bool
    stop_reason: Optional[str]
    message: Optional[str]
    signature: str


def create_runtime_budget_state(
    *,
    max_steps: int,
    max_tool_calls: int,
    max_runtime_seconds: int,
) -> RuntimeBudgetState:
    """Create a fresh per-run budget state for G1 or G2 execution."""
    return RuntimeBudgetState(
        max_steps=max_steps,
        max_tool_calls=max_tool_calls,
        max_runtime_seconds=max_runtime_seconds,
    )


def activate_runtime_budget(state: RuntimeBudgetState) -> Token:
    """Attach one runtime budget state to the current execution context."""
    return _RUNTIME_BUDGET_STATE.set(state)


def deactivate_runtime_budget(token: Token) -> None:
    """Detach the runtime budget state after the request finishes."""
    _RUNTIME_BUDGET_STATE.reset(token)


def get_runtime_budget_state() -> RuntimeBudgetState | None:
    """Return the active runtime budget state, if the current run has one."""
    return _RUNTIME_BUDGET_STATE.get()


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


def sync_runtime_budget_steps(steps_used: int) -> Optional[str]:
    """Store the latest step count and return a stop reason if a limit is exceeded."""
    state = get_runtime_budget_state()
    if state is None:
        return None

    state.steps_used = max(0, int(steps_used))
    elapsed = time.perf_counter() - state.started_at
    if state.steps_used >= state.max_steps or elapsed > state.max_runtime_seconds:
        state.stop_reason = resolve_stop_reason(state.stop_reason, "budget_exceeded")
    return state.stop_reason


def build_budget_summary() -> dict[str, int]:
    """Expose runtime budget counters for traces, metrics, and tests."""
    state = get_runtime_budget_state()
    if state is None:
        return {
            "steps_used": 0,
            "tool_calls_used": 0,
            "duplicate_tool_calls": 0,
            "max_steps": 0,
            "max_tool_calls": 0,
            "max_runtime_seconds": 0,
        }
    return {
        "steps_used": state.steps_used,
        "tool_calls_used": state.tool_calls_used,
        "duplicate_tool_calls": state.duplicate_tool_calls,
        "max_steps": state.max_steps,
        "max_tool_calls": state.max_tool_calls,
        "max_runtime_seconds": state.max_runtime_seconds,
    }


def _normalize_tool_input(raw_input: str, max_chars: int = 240) -> str:
    """Normalize tool input so the dedupe rule stays stable across equivalent text."""
    normalized = str(raw_input or "").translate(_NORMALIZED_WHITESPACE)
    normalized = " ".join(normalized.split())
    if len(normalized) > max_chars:
        return normalized[:max_chars]
    return normalized


def register_tool_call(tool_name: str, raw_input: str) -> ToolCallDecision:
    """Apply tool-call budget and duplicate-call checks for one tool invocation."""
    state = get_runtime_budget_state()
    signature = f"{tool_name}:{_normalize_tool_input(raw_input)}"
    if state is None:
        return ToolCallDecision(True, None, None, signature)

    sync_runtime_budget_steps(state.steps_used)
    if state.stop_reason == "budget_exceeded":
        return ToolCallDecision(
            False,
            "budget_exceeded",
            f"Skipped {tool_name} because the runtime budget was already exhausted.",
            signature,
        )

    if signature in state.seen_tool_signatures:
        state.duplicate_tool_calls += 1
        return ToolCallDecision(
            False,
            None,
            f"Skipped duplicate {tool_name} call because the same input was already processed in this run.",
            signature,
        )

    if state.tool_calls_used >= state.max_tool_calls:
        state.stop_reason = resolve_stop_reason(state.stop_reason, "budget_exceeded")
        return ToolCallDecision(
            False,
            "budget_exceeded",
            f"Skipped {tool_name} because the tool-call budget was exhausted for this run.",
            signature,
        )

    state.tool_calls_used += 1
    state.seen_tool_signatures.add(signature)
    return ToolCallDecision(True, None, None, signature)


def execute_tool_with_runtime_controls(
    tool_name: str,
    raw_input: str,
    tool_func: Callable[[str], str],
) -> str:
    """Run one tool under the active runtime budget and duplicate-call policy."""
    decision = register_tool_call(tool_name, raw_input)
    if not decision.should_execute:
        return str(decision.message or "")
    return str(tool_func(raw_input))


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
