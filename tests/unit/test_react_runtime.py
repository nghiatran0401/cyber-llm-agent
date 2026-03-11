"""Unit tests for shared ReAct runtime helpers."""

from services.api.react_runtime import (
    build_step_trace,
    normalize_stop_reason,
    resolve_stop_reason,
)


def test_normalize_stop_reason_defaults_unknown_values():
    assert normalize_stop_reason("completed") == "completed"
    assert normalize_stop_reason("weird-value", default="completed") == "completed"


def test_resolve_stop_reason_uses_priority_order():
    assert resolve_stop_reason("completed", "needs_human") == "needs_human"
    assert resolve_stop_reason("needs_human", "error") == "error"
    assert resolve_stop_reason("completed", "budget_exceeded") == "budget_exceeded"


def test_build_step_trace_populates_required_fields():
    step = build_step_trace(
        step="RunControl",
        what_it_does="Tracks stop reason.",
        prompt_preview="max_steps=12",
        input_summary="steps_used=2",
        output_summary="stop_reason=completed",
    )
    assert step.step == "RunControl"
    assert step.what_it_does
    assert step.prompt_preview == "max_steps=12"
    assert step.input_summary == "steps_used=2"
    assert step.output_summary == "stop_reason=completed"
