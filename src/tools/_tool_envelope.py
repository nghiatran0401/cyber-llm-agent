"""Shared ToolResult envelope builder for all agent tools."""

import hashlib
import json
from typing import Any


def build_tool_result(
    ok: bool,
    tool: str,
    data: Any = None,
    error: str | None = None,
    error_type: str | None = None,
    duration_ms: int = 0,
    retries: int = 0,
    entries_count: int | None = None,
    input_val: str = "",
) -> dict:
    """Build a standardized tool output envelope.

    Returns a dict with keys: ok, data, error, error_type, meta.
    Callers should json.dumps() the result before returning from Tool.func.
    """
    input_hash = hashlib.sha256((input_val or "").encode()).hexdigest()[:12]
    return {
        "ok": ok,
        "data": data,
        "error": error,
        "error_type": error_type,
        "meta": {
            "tool": tool,
            "duration_ms": duration_ms,
            "retries": retries,
            "entries_count": entries_count,
            "input_hash": input_hash,
        },
    }


def serialize_tool_result(result: dict) -> str:
    """Serialize a ToolResult dict to JSON string for LangChain Tool output."""
    return json.dumps(result, ensure_ascii=True)
