"""Unit tests for shared ReAct runtime helpers."""

from services.api.react_runtime import (
    activate_runtime_budget,
    build_step_trace,
    create_runtime_budget_state,
    deactivate_runtime_budget,
    execute_tool_with_runtime_controls,
    get_runtime_budget_state,
    normalize_stop_reason,
    register_tool_call,
    resolve_stop_reason,
    sync_runtime_budget_steps,
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


def test_register_tool_call_blocks_duplicate_requests():
    state = create_runtime_budget_state(max_steps=4, max_tool_calls=3, max_runtime_seconds=30)
    token = activate_runtime_budget(state)
    try:
        first = register_tool_call("CTIFetch", "ransomware")
        second = register_tool_call("CTIFetch", "ransomware")
        assert first.should_execute is True
        assert second.should_execute is False
        assert "duplicate" in str(second.message).lower()
        assert get_runtime_budget_state().tool_calls_used == 1
        assert get_runtime_budget_state().duplicate_tool_calls == 1
    finally:
        deactivate_runtime_budget(token)


def test_register_tool_call_stops_when_tool_budget_is_exhausted():
    state = create_runtime_budget_state(max_steps=4, max_tool_calls=1, max_runtime_seconds=30)
    token = activate_runtime_budget(state)
    try:
        first = register_tool_call("LogParser", "incident.log")
        second = register_tool_call("CTIFetch", "ransomware")
        assert first.should_execute is True
        assert second.should_execute is False
        assert second.stop_reason == "budget_exceeded"
        assert get_runtime_budget_state().stop_reason == "budget_exceeded"
    finally:
        deactivate_runtime_budget(token)


def test_execute_tool_with_runtime_controls_returns_skip_message_for_duplicates():
    state = create_runtime_budget_state(max_steps=4, max_tool_calls=3, max_runtime_seconds=30)
    token = activate_runtime_budget(state)
    try:
        first = execute_tool_with_runtime_controls("RAGRetriever", "same query", lambda value: f"ran {value}")
        second = execute_tool_with_runtime_controls("RAGRetriever", "same query", lambda value: f"ran {value}")
        assert first == "ran same query"
        assert "Skipped duplicate RAGRetriever" in second
    finally:
        deactivate_runtime_budget(token)


def test_sync_runtime_budget_steps_marks_budget_exceeded():
    state = create_runtime_budget_state(max_steps=2, max_tool_calls=3, max_runtime_seconds=30)
    token = activate_runtime_budget(state)
    try:
        assert sync_runtime_budget_steps(1) is None
        assert sync_runtime_budget_steps(2) == "budget_exceeded"
    finally:
        deactivate_runtime_budget(token)
