"""Extract user input and model output text from heterogeneous agent payloads/results."""

from __future__ import annotations

from typing import Any


def extract_user_text(payload: Any) -> str:
    """Normalize user-facing text from invoke() payloads (dict, tuple messages, or raw)."""
    if isinstance(payload, dict):
        if "input" in payload:
            return str(payload["input"])
        if "messages" in payload and payload["messages"]:
            last = payload["messages"][-1]
            if isinstance(last, tuple) and len(last) == 2:
                return str(last[1])
            return str(last)
    return str(payload)


def extract_response_text(result: Any) -> str:
    """Normalize assistant text from backend invoke() return values."""
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
