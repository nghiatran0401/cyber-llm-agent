"""In-memory request metrics aggregation."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import Lock

_METRICS_LOCK = Lock()
_METRICS_STATE = {
    "requests_total": 0,
    "success_total": 0,
    "error_total": 0,
    "auth_fail_total": 0,
    "rate_limited_total": 0,
    "duration_total_ms": 0,
    "tokens_total_est": 0,
    "cost_total_est_usd": 0.0,
    "tool_calls_total": 0,
    "tool_fail_total": 0,
    "by_endpoint": defaultdict(int),
    "by_mode": defaultdict(int),
    "by_stop_reason": defaultdict(int),
    "recent_runs": deque(maxlen=200),
}


def increment_auth_fail() -> None:
    with _METRICS_LOCK:
        _METRICS_STATE["auth_fail_total"] += 1


def increment_rate_limited() -> None:
    with _METRICS_LOCK:
        _METRICS_STATE["rate_limited_total"] += 1


def record_metric(
    *,
    endpoint: str,
    duration_ms: int,
    success: bool,
    mode: str | None = None,
    stop_reason: str | None = None,
    total_tokens_est: int = 0,
    cost_est_usd: float = 0.0,
    tool_calls: int = 0,
    tool_fail: int = 0,
    run_id: str | None = None,
    model: str | None = None,
) -> None:
    with _METRICS_LOCK:
        _METRICS_STATE["requests_total"] += 1
        _METRICS_STATE["duration_total_ms"] += max(0, int(duration_ms))
        _METRICS_STATE["tokens_total_est"] += max(0, int(total_tokens_est))
        _METRICS_STATE["cost_total_est_usd"] += max(0.0, float(cost_est_usd))
        _METRICS_STATE["tool_calls_total"] += max(0, int(tool_calls))
        _METRICS_STATE["tool_fail_total"] += max(0, int(tool_fail))
        _METRICS_STATE["by_endpoint"][endpoint] += 1
        _METRICS_STATE["by_mode"][mode or "none"] += 1
        _METRICS_STATE["by_stop_reason"][stop_reason or ("completed" if success else "error")] += 1
        if success:
            _METRICS_STATE["success_total"] += 1
        else:
            _METRICS_STATE["error_total"] += 1
        _METRICS_STATE["recent_runs"].appendleft(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "run_id": run_id,
                "endpoint": endpoint,
                "mode": mode,
                "model": model,
                "success": success,
                "stop_reason": stop_reason or ("completed" if success else "error"),
                "duration_ms": int(duration_ms),
                "total_tokens_est": int(total_tokens_est),
                "cost_est_usd": round(float(cost_est_usd), 6),
                "tool_calls": int(tool_calls),
                "tool_fail": int(tool_fail),
            }
        )


def get_snapshot() -> dict:
    """Return a thread-safe snapshot of all metrics."""
    with _METRICS_LOCK:
        return {
            "requests_total": int(_METRICS_STATE["requests_total"]),
            "success_total": int(_METRICS_STATE["success_total"]),
            "error_total": int(_METRICS_STATE["error_total"]),
            "auth_fail_total": int(_METRICS_STATE["auth_fail_total"]),
            "rate_limited_total": int(_METRICS_STATE["rate_limited_total"]),
            "duration_total_ms": int(_METRICS_STATE["duration_total_ms"]),
            "tokens_total_est": int(_METRICS_STATE["tokens_total_est"]),
            "cost_total_est_usd": float(_METRICS_STATE["cost_total_est_usd"]),
            "tool_calls_total": int(_METRICS_STATE["tool_calls_total"]),
            "tool_fail_total": int(_METRICS_STATE["tool_fail_total"]),
            "by_endpoint": dict(_METRICS_STATE["by_endpoint"]),
            "by_mode": dict(_METRICS_STATE["by_mode"]),
            "by_stop_reason": dict(_METRICS_STATE["by_stop_reason"]),
            "recent_runs": list(_METRICS_STATE["recent_runs"]),
        }
