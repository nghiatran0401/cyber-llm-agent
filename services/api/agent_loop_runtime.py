"""Shared agent-loop runtime: trace shape, budgets, stop reasons, and tool-call policy.

This is the execution harness for tool-using (ReAct-style) G1/G2 runs—not React.js.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass, field
import os
import re
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
_NON_ALNUM_RE = re.compile(r"[^a-z0-9._/-]+")
_FILLER_TOKENS = {
    "a",
    "an",
    "the",
    "and",
    "or",
    "possible",
    "potential",
    "likely",
    "activity",
    "attack",
    "behavior",
    "behaviour",
    "incident",
    "suspicious",
    "detected",
    "pattern",
    "patterns",
    "query",
    "context",
    "lookup",
    "intel",
    "evidence",
}
_CANONICAL_INTENT_RULES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("ransomware", "encrypt", "locker"), "threat:ransomware"),
    (("phish", "credential harvest", "credential steal"), "threat:phishing"),
    (("sql injection", "sqli"), "threat:sql_injection"),
    (("xss", "cross site scripting"), "threat:xss"),
    (("brute force", "credential stuffing", "password spray", "failed login", "auth"), "threat:credential_attack"),
    (("ddos", "dos", "port scan", "network scan", "scan"), "threat:network_disruption"),
)
_RUNTIME_BUDGET_STATE: ContextVar["RuntimeBudgetState | None"] = ContextVar(
    "agent_loop_budget_state",
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
    semantic_duplicate_tool_calls: int = 0
    cached_tool_reuses: int = 0
    cooldown_skips: int = 0
    tool_failures: int = 0
    stop_reason: Optional[str] = None
    seen_tool_signatures: set[str] = field(default_factory=set)
    seen_tool_intents: set[str] = field(default_factory=set)
    tool_result_cache: dict[str, str] = field(default_factory=dict)
    failed_tool_intents: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class ToolCallDecision:
    """Describe whether a tool call should execute under the active runtime policy."""

    should_execute: bool
    stop_reason: Optional[str]
    message: Optional[str]
    signature: str
    intent_signature: str
    reused_output: Optional[str] = None
    decision_type: str = "execute"


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
            "semantic_duplicate_tool_calls": 0,
            "cached_tool_reuses": 0,
            "cooldown_skips": 0,
            "tool_failures": 0,
            "max_steps": 0,
            "max_tool_calls": 0,
            "max_runtime_seconds": 0,
        }
    return {
        "steps_used": state.steps_used,
        "tool_calls_used": state.tool_calls_used,
        "duplicate_tool_calls": state.duplicate_tool_calls,
        "semantic_duplicate_tool_calls": state.semantic_duplicate_tool_calls,
        "cached_tool_reuses": state.cached_tool_reuses,
        "cooldown_skips": state.cooldown_skips,
        "tool_failures": state.tool_failures,
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


def _tokenize_for_intent(raw_input: str) -> list[str]:
    """Produce stable tokens for rule-based semantic dedupe without another model call."""
    normalized = _normalize_tool_input(raw_input).lower()
    normalized = _NON_ALNUM_RE.sub(" ", normalized)
    return [token for token in normalized.split() if token and token not in _FILLER_TOKENS]


def _canonicalize_tool_intent(tool_name: str, raw_input: str) -> str:
    """Map semantically similar tool requests to one deterministic intent key.

    This keeps runtime controls predictable and testable. The project does not
    rely on another model to dedupe tool calls because deterministic policies
    are easier to explain, benchmark, and debug.
    """

    normalized = _normalize_tool_input(raw_input).lower()
    if tool_name == "LogParser":
        filename = os.path.basename(normalized)
        return filename or normalized or "empty"

    for markers, canonical in _CANONICAL_INTENT_RULES:
        if any(marker in normalized for marker in markers):
            return canonical

    tokens = _tokenize_for_intent(raw_input)
    if tool_name == "CTIFetch":
        return ":".join(tokens[:3]) or "generic-threat"
    if tool_name == "RAGRetriever":
        return ":".join(tokens[:4]) or "generic-context"
    return ":".join(tokens[:3]) or normalized or "generic"


def _record_tool_failure() -> None:
    """Increment per-run tool failure counter when a tool returns unusable output."""
    state = get_runtime_budget_state()
    if state is not None:
        state.tool_failures += 1


def _normalize_tool_output(tool_name: str, raw_output: object) -> str:
    """Normalize tool output so blank or malformed results degrade to deterministic text."""
    text = str(raw_output or "").strip()
    if text:
        return text
    _record_tool_failure()
    return f"{tool_name} returned no usable output for this request."


def _store_tool_result(signature: str, intent_signature: str, output_text: str) -> None:
    """Cache successful tool output by exact signature and semantic intent key."""
    state = get_runtime_budget_state()
    if state is None:
        return
    state.tool_result_cache[signature] = output_text
    state.tool_result_cache[intent_signature] = output_text


def _mark_failed_intent(intent_signature: str) -> None:
    """Remember failed intents so semantically equivalent retries can cool down."""
    state = get_runtime_budget_state()
    if state is None:
        return
    state.failed_tool_intents.add(intent_signature)


def register_tool_call(tool_name: str, raw_input: str) -> ToolCallDecision:
    """Apply tool-call budget and duplicate-call checks for one tool invocation."""
    state = get_runtime_budget_state()
    signature = f"{tool_name}:{_normalize_tool_input(raw_input)}"
    intent_signature = f"{tool_name}:{_canonicalize_tool_intent(tool_name, raw_input)}"
    if state is None:
        return ToolCallDecision(True, None, None, signature, intent_signature)

    sync_runtime_budget_steps(state.steps_used)
    if state.stop_reason == "budget_exceeded":
        return ToolCallDecision(
            False,
            "budget_exceeded",
            f"Skipped {tool_name} because the runtime budget was already exhausted.",
            signature,
            intent_signature,
            decision_type="budget_exceeded",
        )

    if signature in state.seen_tool_signatures:
        state.duplicate_tool_calls += 1
        cached_output = state.tool_result_cache.get(signature) or state.tool_result_cache.get(intent_signature)
        if cached_output:
            state.cached_tool_reuses += 1
        return ToolCallDecision(
            False,
            None,
            f"Skipped duplicate {tool_name} call because the same input was already processed in this run.",
            signature,
            intent_signature,
            reused_output=cached_output,
            decision_type="duplicate_reuse" if cached_output else "duplicate_skip",
        )

    if intent_signature in state.failed_tool_intents:
        state.cooldown_skips += 1
        return ToolCallDecision(
            False,
            None,
            f"Skipped {tool_name} because a semantically equivalent request already failed in this run.",
            signature,
            intent_signature,
            decision_type="cooldown_skip",
        )

    cached_output = state.tool_result_cache.get(intent_signature)
    if cached_output:
        state.duplicate_tool_calls += 1
        state.semantic_duplicate_tool_calls += 1
        state.cached_tool_reuses += 1
        state.seen_tool_signatures.add(signature)
        state.seen_tool_intents.add(intent_signature)
        return ToolCallDecision(
            False,
            None,
            f"Reused cached {tool_name} output for a semantically equivalent request.",
            signature,
            intent_signature,
            reused_output=cached_output,
            decision_type="semantic_reuse",
        )

    if state.tool_calls_used >= state.max_tool_calls:
        state.stop_reason = resolve_stop_reason(state.stop_reason, "budget_exceeded")
        return ToolCallDecision(
            False,
            "budget_exceeded",
            f"Skipped {tool_name} because the tool-call budget was exhausted for this run.",
            signature,
            intent_signature,
            decision_type="budget_exceeded",
        )

    state.tool_calls_used += 1
    state.seen_tool_signatures.add(signature)
    state.seen_tool_intents.add(intent_signature)
    return ToolCallDecision(True, None, None, signature, intent_signature)


def execute_tool_with_runtime_controls(
    tool_name: str,
    raw_input: str,
    tool_func: Callable[[str], str],
) -> str:
    """Run one tool under the active runtime budget and duplicate-call policy."""
    decision = register_tool_call(tool_name, raw_input)
    if not decision.should_execute:
        if decision.reused_output:
            return str(decision.reused_output)
        return str(decision.message or "")
    try:
        output_text = _normalize_tool_output(tool_name, tool_func(raw_input))
        if "returned no usable output" in output_text.lower():
            _mark_failed_intent(decision.intent_signature)
            return output_text
        _store_tool_result(decision.signature, decision.intent_signature, output_text)
        return output_text
    except Exception:
        _record_tool_failure()
        _mark_failed_intent(decision.intent_signature)
        return f"{tool_name} is temporarily unavailable because tool execution failed."


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
