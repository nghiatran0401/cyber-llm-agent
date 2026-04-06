"""Unit tests for shared agent-loop runtime (ReAct-style tool loop, not React.js)."""

from services.api.agent_loop_runtime import (
    activate_runtime_budget,
    build_budget_summary,
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
        assert second == "ran same query"
        assert build_budget_summary()["cached_tool_reuses"] == 1
    finally:
        deactivate_runtime_budget(token)


def test_execute_tool_with_runtime_controls_reuses_semantically_equivalent_requests():
    state = create_runtime_budget_state(max_steps=4, max_tool_calls=3, max_runtime_seconds=30)
    token = activate_runtime_budget(state)
    tool_runs = {"count": 0}

    def _tool(_value: str) -> str:
        tool_runs["count"] += 1
        return "cached CTI evidence"

    try:
        first = execute_tool_with_runtime_controls("CTIFetch", "possible ransomware activity", _tool)
        second = execute_tool_with_runtime_controls("CTIFetch", "ransomware attack", _tool)
        assert first == "cached CTI evidence"
        assert second == "cached CTI evidence"
        assert tool_runs["count"] == 1
        summary = build_budget_summary()
        assert summary["tool_calls_used"] == 1
        assert summary["duplicate_tool_calls"] == 1
        assert summary["semantic_duplicate_tool_calls"] == 1
        assert summary["cached_tool_reuses"] == 1
    finally:
        deactivate_runtime_budget(token)


def test_execute_tool_with_runtime_controls_cools_down_failed_semantic_retry():
    state = create_runtime_budget_state(max_steps=4, max_tool_calls=3, max_runtime_seconds=30)
    token = activate_runtime_budget(state)

    try:
        first = execute_tool_with_runtime_controls("CTIFetch", "possible ransomware activity", lambda _value: 1 / 0)
        second = execute_tool_with_runtime_controls("CTIFetch", "ransomware attack", lambda _value: "should not run")
        assert first == "CTIFetch is temporarily unavailable because tool execution failed."
        assert "semantically equivalent request already failed" in second
        summary = build_budget_summary()
        assert summary["tool_calls_used"] == 1
        assert summary["tool_failures"] == 1
        assert summary["cooldown_skips"] == 1
    finally:
        deactivate_runtime_budget(token)


def test_execute_tool_with_runtime_controls_handles_empty_tool_output():
    state = create_runtime_budget_state(max_steps=4, max_tool_calls=3, max_runtime_seconds=30)
    token = activate_runtime_budget(state)
    try:
        result = execute_tool_with_runtime_controls("LogParser", "incident.log", lambda _value: "")
        assert result == "LogParser returned no usable output for this request."
        assert build_budget_summary()["tool_failures"] == 1
    finally:
        deactivate_runtime_budget(token)


def test_execute_tool_with_runtime_controls_handles_tool_exception():
    state = create_runtime_budget_state(max_steps=4, max_tool_calls=3, max_runtime_seconds=30)
    token = activate_runtime_budget(state)
    try:
        result = execute_tool_with_runtime_controls("CTIFetch", "ransomware", lambda _value: 1 / 0)
        assert result == "CTIFetch is temporarily unavailable because tool execution failed."
        assert build_budget_summary()["tool_failures"] == 1
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
