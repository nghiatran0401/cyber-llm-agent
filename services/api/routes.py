"""API route handlers extracted from main.py."""

from __future__ import annotations

import json
import re
from pathlib import Path
from queue import Empty, Queue
from threading import Thread
from time import perf_counter
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from src.config.settings import Settings
from src.utils.logger import setup_logger, log_structured

from .metrics import get_snapshot, record_metric
from .schemas import (
    AnalyzeRequest,
    ApiResponse,
    ChatRequest,
    ErrorInfo,
    ResponseMeta,
    SandboxAnalyzeRequest,
    SandboxSimulateRequest,
    StepTrace,
    WorkspaceStreamRequest,
)
from .g1_service import (
    run_chat,
    run_g1_analysis,
    run_workspace_with_progress,
)
from .g2_service import run_g2_analysis
from .sandbox_service import (
    analyze_sandbox_event,
    get_sandbox_scenarios,
    simulate_sandbox_event,
)

logger = setup_logger(__name__)

router = APIRouter(prefix="/api/v1")

_RUN_CONTROL_TOOL_CALLS_RE = re.compile(r"tool_calls_used=(\d+)")
_RUN_CONTROL_DUPLICATES_RE = re.compile(r"duplicate_tool_calls=(\d+)")
_RUN_CONTROL_SEMANTIC_DUPLICATES_RE = re.compile(r"semantic_duplicate_tool_calls=(\d+)")
_RUN_CONTROL_CACHE_REUSES_RE = re.compile(r"cached_tool_reuses=(\d+)")
_RUN_CONTROL_COOLDOWN_SKIPS_RE = re.compile(r"cooldown_skips=(\d+)")
_RUN_CONTROL_TOOL_FAILURES_RE = re.compile(r"tool_failures=(\d+)")

_OWASP_MITRE_MAP = {
    "A01_BrokenAccessControl": {
        "owasp": "A01:2021 Broken Access Control",
        "mitre": ["T1190", "T1068"],
    },
    "A02_CryptographicFailures": {
        "owasp": "A02:2021 Cryptographic Failures",
        "mitre": ["T1557", "T1040"],
    },
    "A03_Injection": {
        "owasp": "A03:2021 Injection",
        "mitre": ["T1190", "T1059"],
    },
    "A05_SecurityMisconfiguration": {
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": ["T1190", "T1580"],
    },
    "A06_VulnerableComponents": {
        "owasp": "A06:2021 Vulnerable and Outdated Components",
        "mitre": ["T1195", "T1588"],
    },
    "A07_IdentificationAuthFailures": {
        "owasp": "A07:2021 Identification and Authentication Failures",
        "mitre": ["T1110", "T1078"],
    },
    "A08_SoftwareDataIntegrityFailures": {
        "owasp": "A08:2021 Software and Data Integrity Failures",
        "mitre": ["T1553", "T1195"],
    },
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _estimate_tokens(text: str) -> int:
    content = str(text or "")
    if not content.strip():
        return 0
    return max(1, len(content) // 4)


def _extract_text_payload(value) -> str:
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=True)
    return str(value or "")


def _derive_tool_stats(result, trace) -> tuple[int, int, int, int, int, int, int]:
    statuses: dict[str, bool] = {}
    budget_tool_calls = 0
    duplicate_tool_calls = 0
    semantic_duplicate_tool_calls = 0
    cached_tool_reuses = 0
    cooldown_skips = 0
    explicit_tool_failures = 0
    if isinstance(result, dict):
        for key, tool_name in (
            ("log_evidence", "LogParser"),
            ("cti_evidence", "CTIFetch"),
            ("rag_context", "RAGRetriever"),
        ):
            raw = str(result.get(key, "")).strip()
            if not raw:
                continue
            failed = any(marker in raw.lower() for marker in ("error", "unavailable", "no relevant context"))
            statuses[tool_name] = not failed

    result_text = _extract_text_payload(result).lower()
    if "source:" in result_text and "CTIFetch" not in statuses:
        statuses["CTIFetch"] = True
    if "#chunk-" in result_text and "RAGRetriever" not in statuses:
        statuses["RAGRetriever"] = True
    if (
        "RAGRetriever" not in statuses
        and "retrieved context" in result_text
        and "citations:" in result_text
    ):
        statuses["RAGRetriever"] = True

    for item in trace or []:
        step_name = item.get("step") if isinstance(item, dict) else getattr(item, "step", "")
        input_summary = item.get("input_summary", "") if isinstance(item, dict) else getattr(item, "input_summary", "")
        output_summary = item.get("output_summary", "") if isinstance(item, dict) else getattr(item, "output_summary", "")
        if step_name == "WorkerTask":
            statuses.setdefault("WorkerTask", True)
        if step_name in ("RunControl", "ExecutionSummary"):
            match = _RUN_CONTROL_TOOL_CALLS_RE.search(str(output_summary)) or _RUN_CONTROL_TOOL_CALLS_RE.search(
                str(input_summary)
            )
            if match:
                budget_tool_calls = max(budget_tool_calls, int(match.group(1)))
            duplicate_match = _RUN_CONTROL_DUPLICATES_RE.search(str(input_summary))
            if duplicate_match:
                duplicate_tool_calls = max(duplicate_tool_calls, int(duplicate_match.group(1)))
            semantic_duplicate_match = _RUN_CONTROL_SEMANTIC_DUPLICATES_RE.search(str(input_summary))
            if semantic_duplicate_match:
                semantic_duplicate_tool_calls = max(
                    semantic_duplicate_tool_calls, int(semantic_duplicate_match.group(1))
                )
            cache_reuse_match = _RUN_CONTROL_CACHE_REUSES_RE.search(str(input_summary))
            if cache_reuse_match:
                cached_tool_reuses = max(cached_tool_reuses, int(cache_reuse_match.group(1)))
            cooldown_skip_match = _RUN_CONTROL_COOLDOWN_SKIPS_RE.search(str(input_summary))
            if cooldown_skip_match:
                cooldown_skips = max(cooldown_skips, int(cooldown_skip_match.group(1)))
            failure_match = _RUN_CONTROL_TOOL_FAILURES_RE.search(str(output_summary))
            if not failure_match:
                failure_match = _RUN_CONTROL_TOOL_FAILURES_RE.search(str(input_summary))
            if failure_match:
                explicit_tool_failures = max(explicit_tool_failures, int(failure_match.group(1)))

    tool_calls = max(len(statuses), budget_tool_calls)
    tool_success = sum(1 for ok in statuses.values() if ok)
    tool_fail = max(explicit_tool_failures, max(0, tool_calls - tool_success))
    return (
        tool_calls,
        tool_success,
        tool_fail,
        duplicate_tool_calls,
        semantic_duplicate_tool_calls,
        cached_tool_reuses,
        cooldown_skips,
    )


def _enrich_trace_step(item, *, run_id: str, step_index: int) -> StepTrace:
    """Normalize one trace step for API responses and SSE streaming."""
    if hasattr(item, "model_dump"):
        payload = item.model_dump()
    elif isinstance(item, dict):
        payload = dict(item)
    else:
        payload = {
            "step": "Unknown",
            "what_it_does": "",
            "prompt_preview": "",
            "input_summary": "",
            "output_summary": "",
        }
    payload["run_id"] = run_id
    payload["step_id"] = payload.get("step_id") or f"{run_id}-s{step_index:03d}"
    if payload.get("step") in {"WorkerTask", "SingleAgentExecution", "LogAnalyzer", "ThreatPredictor"}:
        payload["tool_call_id"] = payload.get("tool_call_id") or f"{run_id}-t{step_index:03d}"
    return StepTrace(**payload)


def _enrich_trace(trace, run_id: str):
    enriched: list[StepTrace] = []
    for idx, item in enumerate(trace or [], start=1):
        enriched.append(_enrich_trace_step(item, run_id=run_id, step_index=idx))
    return enriched


def _build_success_response(
    request_id: str,
    mode: str | None,
    model: str | None,
    result,
    trace,
    start_time: float,
    stop_reason: str | None = None,
    steps_used: int | None = None,
    prompt_version: str | None = None,
    rubric_score: float | None = None,
    rubric_label: str | None = None,
    endpoint: str | None = None,
    input_text: str = "",
) -> ApiResponse:
    duration_ms = int((perf_counter() - start_time) * 1000)
    run_id = request_id
    enriched_trace = _enrich_trace(trace, run_id=run_id)
    input_tokens_est = _estimate_tokens(input_text)
    output_tokens_est = _estimate_tokens(_extract_text_payload(result))
    total_tokens_est = input_tokens_est + output_tokens_est
    cost_est_usd = round((total_tokens_est / 1000) * 0.0005, 6)
    (
        tool_calls,
        tool_success,
        tool_fail,
        duplicate_tool_calls,
        semantic_duplicate_tool_calls,
        cached_tool_reuses,
        cooldown_skips,
    ) = _derive_tool_stats(result=result, trace=enriched_trace)

    if endpoint:
        record_metric(
            endpoint=endpoint,
            duration_ms=duration_ms,
            success=True,
            mode=mode,
            stop_reason=stop_reason,
            total_tokens_est=total_tokens_est,
            cost_est_usd=cost_est_usd,
            tool_calls=tool_calls,
            tool_fail=tool_fail,
            duplicate_tool_calls=duplicate_tool_calls,
            semantic_duplicate_tool_calls=semantic_duplicate_tool_calls,
            cached_tool_reuses=cached_tool_reuses,
            cooldown_skips=cooldown_skips,
            run_id=run_id,
            model=model,
        )
    log_structured(
        logger,
        "info",
        "api_request_completed",
        run_id=run_id,
        endpoint=endpoint,
        mode=mode,
        model=model,
        duration_ms=duration_ms,
        total_tokens_est=total_tokens_est,
        cost_est_usd=cost_est_usd,
        tool_calls=tool_calls,
        tool_fail=tool_fail,
        duplicate_tool_calls=duplicate_tool_calls,
        semantic_duplicate_tool_calls=semantic_duplicate_tool_calls,
        cached_tool_reuses=cached_tool_reuses,
        cooldown_skips=cooldown_skips,
    )
    return ApiResponse(
        ok=True,
        result=result,
        trace=enriched_trace,
        meta=ResponseMeta(
            request_id=request_id,
            run_id=run_id,
            mode=mode,
            model=model,
            duration_ms=duration_ms,
            stop_reason=stop_reason,
            steps_used=steps_used,
            prompt_version=prompt_version,
            rubric_score=rubric_score,
            rubric_label=rubric_label,
            input_tokens_est=input_tokens_est,
            output_tokens_est=output_tokens_est,
            total_tokens_est=total_tokens_est,
            cost_est_usd=cost_est_usd,
            tool_calls=tool_calls,
            tool_success=tool_success,
            tool_fail=tool_fail,
        ),
        error=None,
    )


def _normalize_analysis_result(payload, fallback_steps: int = 1):
    """Support both old and new service return tuple shapes."""
    if isinstance(payload, tuple):
        if len(payload) == 8:
            return payload
        if len(payload) == 5:
            result, trace, model, stop_reason, steps_used = payload
            return result, trace, model, stop_reason, steps_used, None, None, None
        if len(payload) == 3:
            result, trace, model = payload
            steps = len(trace) if isinstance(trace, list) and trace else fallback_steps
            return result, trace, model, "completed", steps, None, None, None
    raise TypeError("Unexpected service response shape.")


def _normalize_workspace_result(payload):
    """Support both old and new workspace return tuple shapes."""
    if isinstance(payload, tuple):
        if len(payload) == 7:
            return payload
        if len(payload) == 4:
            result, model, stop_reason, steps_used = payload
            return result, model, stop_reason, steps_used, None, None, None
        if len(payload) == 2:
            result, model = payload
            return result, model, "completed", 1, None, None, None
    raise TypeError("Unexpected workspace response shape.")


def _tail_jsonl(path: Path, limit: int) -> list[dict]:
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as handle:
        lines = [line.strip() for line in handle.readlines() if line.strip()]
    selected = lines[-limit:]
    result: list[dict] = []
    for line in reversed(selected):
        try:
            payload = json.loads(line)
            if isinstance(payload, dict):
                result.append(payload)
            else:
                result.append({"raw": payload})
        except json.JSONDecodeError:
            result.append({"raw": line})
    return result


# ── Health & Observability ─────────────────────────────────────────────────────

@router.get("/health", response_model=ApiResponse)
def health() -> ApiResponse:
    request_id = str(uuid4())
    return ApiResponse(
        ok=True,
        result={
            "status": "healthy",
            "sandbox_enabled": True,
        },
        trace=[],
        meta=ResponseMeta(request_id=request_id, mode=None, model=None, duration_ms=0),
        error=None,
    )


@router.get("/ready", response_model=ApiResponse)
def ready() -> ApiResponse:
    request_id = str(uuid4())
    Settings.validate()
    return ApiResponse(
        ok=True,
        result={"status": "ready"},
        trace=[],
        meta=ResponseMeta(request_id=request_id, mode=None, model=None, duration_ms=0),
        error=None,
    )


@router.get("/metrics", response_model=ApiResponse)
def metrics() -> ApiResponse:
    request_id = str(uuid4())
    snap = get_snapshot()
    requests_total = snap["requests_total"]
    avg_duration_ms = round(snap["duration_total_ms"] / requests_total, 2) if requests_total else 0.0
    avg_tool_calls_per_run = round(snap["tool_calls_total"] / requests_total, 4) if requests_total else 0.0
    return ApiResponse(
        ok=True,
        result={
            "requests_total": requests_total,
            "success_total": snap["success_total"],
            "error_total": snap["error_total"],
            "avg_duration_ms": avg_duration_ms,
            "tokens_total_est": snap["tokens_total_est"],
            "cost_total_est_usd": round(snap["cost_total_est_usd"], 6),
            "tool_calls_total": snap["tool_calls_total"],
            "tool_fail_total": snap["tool_fail_total"],
            "duplicate_tool_calls_total": snap["duplicate_tool_calls_total"],
            "semantic_duplicate_tool_calls_total": snap["semantic_duplicate_tool_calls_total"],
            "cached_tool_reuses_total": snap["cached_tool_reuses_total"],
            "cooldown_skips_total": snap["cooldown_skips_total"],
            "avg_tool_calls_per_run": avg_tool_calls_per_run,
            "by_endpoint": snap["by_endpoint"],
            "by_mode": snap["by_mode"],
            "by_stop_reason": snap["by_stop_reason"],
        },
        trace=[],
        meta=ResponseMeta(request_id=request_id, run_id=request_id, mode=None, model=None, duration_ms=0),
        error=None,
    )


@router.get("/metrics/dashboard", response_model=ApiResponse)
def metrics_dashboard() -> ApiResponse:
    request_id = str(uuid4())
    snap = get_snapshot()
    requests_total = snap["requests_total"]
    success_rate = round((snap["success_total"] / requests_total) * 100, 2) if requests_total else 0.0
    avg_duration_ms = round(snap["duration_total_ms"] / requests_total, 2) if requests_total else 0.0
    avg_tokens = round(snap["tokens_total_est"] / requests_total, 2) if requests_total else 0.0
    avg_tool_calls_per_run = round(snap["tool_calls_total"] / requests_total, 4) if requests_total else 0.0

    return ApiResponse(
        ok=True,
        result={
            "summary": {
                "requests_total": requests_total,
                "success_total": snap["success_total"],
                "error_total": snap["error_total"],
                "success_rate_pct": success_rate,
                "avg_duration_ms": avg_duration_ms,
                "avg_tokens_est": avg_tokens,
                "cost_total_est_usd": round(snap["cost_total_est_usd"], 6),
                "avg_tool_calls_per_run": avg_tool_calls_per_run,
            },
            "breakdown": {
                "by_mode": snap["by_mode"],
                "by_stop_reason": snap["by_stop_reason"],
                "duplicate_tool_calls_total": snap["duplicate_tool_calls_total"],
                "semantic_duplicate_tool_calls_total": snap["semantic_duplicate_tool_calls_total"],
                "cached_tool_reuses_total": snap["cached_tool_reuses_total"],
                "cooldown_skips_total": snap["cooldown_skips_total"],
            },
            "recent_runs": snap["recent_runs"][:25],
        },
        trace=[],
        meta=ResponseMeta(request_id=request_id, run_id=request_id, mode=None, model=None, duration_ms=0),
        error=None,
    )


@router.get("/detections/recent", response_model=ApiResponse)
def detections_recent(limit: int = Query(default=25, ge=1, le=100)) -> ApiResponse:
    request_id = str(uuid4())
    snap = get_snapshot()
    filtered = []
    for run in snap["recent_runs"]:
        endpoint = str(run.get("endpoint", ""))
        if endpoint in {"/api/v1/analyze/g1", "/api/v1/analyze/g2", "/api/v1/sandbox/analyze"}:
            filtered.append(
                {
                    "timestamp": run.get("timestamp"),
                    "run_id": run.get("run_id"),
                    "endpoint": endpoint,
                    "mode": run.get("mode"),
                    "success": run.get("success"),
                    "stop_reason": run.get("stop_reason"),
                    "duration_ms": run.get("duration_ms"),
                    "total_tokens_est": run.get("total_tokens_est"),
                    "tool_calls": run.get("tool_calls"),
                    "tool_fail": run.get("tool_fail"),
                }
            )
        if len(filtered) >= limit:
            break
    return ApiResponse(
        ok=True,
        result={"items": filtered, "count": len(filtered)},
        trace=[],
        meta=ResponseMeta(request_id=request_id, run_id=request_id, mode=None, model=None, duration_ms=0),
        error=None,
    )


# ── Knowledge ──────────────────────────────────────────────────────────────────

@router.get("/knowledge/owasp-mitre-map", response_model=ApiResponse)
def owasp_mitre_map() -> ApiResponse:
    request_id = str(uuid4())
    return ApiResponse(
        ok=True,
        result=_OWASP_MITRE_MAP,
        trace=[],
        meta=ResponseMeta(request_id=request_id, run_id=request_id, mode=None, model=None, duration_ms=0),
        error=None,
    )


# ── Analysis ───────────────────────────────────────────────────────────────────

@router.post("/analyze/g1", response_model=ApiResponse)
def analyze_g1(payload: AnalyzeRequest) -> ApiResponse:
    request_id = str(uuid4())
    start_time = perf_counter()
    try:
        response, trace, model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label = (
            _normalize_analysis_result(
            run_g1_analysis(payload.input, session_id=payload.session_id)
        )
        )
        return _build_success_response(
            request_id=request_id,
            mode="g1",
            model=model,
            result=response,
            trace=trace if payload.include_trace else [],
            start_time=start_time,
            stop_reason=stop_reason,
            steps_used=steps_used,
            prompt_version=prompt_version,
            rubric_score=rubric_score,
            rubric_label=rubric_label,
            endpoint="/api/v1/analyze/g1",
            input_text=payload.input,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/analyze/g2", response_model=ApiResponse)
def analyze_g2(payload: AnalyzeRequest) -> ApiResponse:
    request_id = str(uuid4())
    start_time = perf_counter()
    try:
        result, trace, model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label = (
            _normalize_analysis_result(run_g2_analysis(payload.input))
        )
        return _build_success_response(
            request_id=request_id,
            mode="g2",
            model=model,
            result=result,
            trace=trace if payload.include_trace else [],
            start_time=start_time,
            stop_reason=stop_reason,
            steps_used=steps_used,
            prompt_version=prompt_version,
            rubric_score=rubric_score,
            rubric_label=rubric_label,
            endpoint="/api/v1/analyze/g2",
            input_text=payload.input,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/chat", response_model=ApiResponse)
def chat(payload: ChatRequest) -> ApiResponse:
    request_id = str(uuid4())
    start_time = perf_counter()
    try:
        response, trace, model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label = (
            _normalize_analysis_result(
            run_chat(payload.input, mode=payload.mode, session_id=payload.session_id)
        )
        )
        return _build_success_response(
            request_id=request_id,
            mode=payload.mode,
            model=model,
            result=response,
            trace=trace if payload.include_trace else [],
            start_time=start_time,
            stop_reason=stop_reason,
            steps_used=steps_used,
            prompt_version=prompt_version,
            rubric_score=rubric_score,
            rubric_label=rubric_label,
            endpoint="/api/v1/chat",
            input_text=payload.input,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ── Streaming ──────────────────────────────────────────────────────────────────

@router.post("/workspace/stream")
def workspace_stream(payload: WorkspaceStreamRequest):
    """Stream progress events for workspace requests (SSE)."""
    request_id = str(uuid4())
    run_id = request_id
    event_queue: Queue[dict] = Queue()
    start_time = perf_counter()
    def _put_event(event_type: str, **data):
        event_queue.put({"type": event_type, **data})

    def _runner():
        try:
            trace_for_metrics: list[StepTrace] = []
            step_index = 0

            def _on_step(step: StepTrace):
                nonlocal step_index
                step_index += 1
                enriched = _enrich_trace_step(step, run_id=run_id, step_index=step_index)
                trace_for_metrics.append(enriched)
                _put_event("trace", step=enriched.model_dump())

            result, model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label = (
                _normalize_workspace_result(
                run_workspace_with_progress(
                task=payload.task,
                mode=payload.mode,
                user_input=payload.input,
                on_step=_on_step,
                session_id=payload.session_id,
            )
            )
            )

            duration_ms = int((perf_counter() - start_time) * 1000)
            input_tokens_est = _estimate_tokens(payload.input)
            output_tokens_est = _estimate_tokens(_extract_text_payload(result))
            total_tokens_est = input_tokens_est + output_tokens_est
            cost_est_usd = round((total_tokens_est / 1000) * 0.0005, 6)
            (
                tool_calls,
                tool_success,
                tool_fail,
                duplicate_tool_calls,
                semantic_duplicate_tool_calls,
                cached_tool_reuses,
                cooldown_skips,
            ) = _derive_tool_stats(result=result, trace=trace_for_metrics)
            record_metric(
                endpoint="/api/v1/workspace/stream",
                duration_ms=duration_ms,
                success=True,
                mode=payload.mode,
                stop_reason=stop_reason,
                total_tokens_est=total_tokens_est,
                cost_est_usd=cost_est_usd,
                tool_calls=tool_calls,
                tool_fail=tool_fail,
                duplicate_tool_calls=duplicate_tool_calls,
                semantic_duplicate_tool_calls=semantic_duplicate_tool_calls,
                cached_tool_reuses=cached_tool_reuses,
                cooldown_skips=cooldown_skips,
                run_id=run_id,
                model=model,
            )
            log_structured(
                logger,
                "info",
                "workspace_stream_completed",
                run_id=run_id,
                mode=payload.mode,
                duration_ms=duration_ms,
                total_tokens_est=total_tokens_est,
                cost_est_usd=cost_est_usd,
                tool_calls=tool_calls,
                tool_fail=tool_fail,
                duplicate_tool_calls=duplicate_tool_calls,
                semantic_duplicate_tool_calls=semantic_duplicate_tool_calls,
                cached_tool_reuses=cached_tool_reuses,
                cooldown_skips=cooldown_skips,
            )
            _put_event(
                "final",
                result=result,
                meta=ResponseMeta(
                    request_id=request_id,
                    run_id=run_id,
                    mode=payload.mode,
                    model=model,
                    duration_ms=duration_ms,
                    stop_reason=stop_reason,
                    steps_used=steps_used,
                    prompt_version=prompt_version,
                    rubric_score=rubric_score,
                    rubric_label=rubric_label,
                    input_tokens_est=input_tokens_est,
                    output_tokens_est=output_tokens_est,
                    total_tokens_est=total_tokens_est,
                    cost_est_usd=cost_est_usd,
                    tool_calls=tool_calls,
                    tool_success=tool_success,
                    tool_fail=tool_fail,
                ).model_dump(),
            )
        except Exception as exc:
            _put_event("error", error={"code": "STREAM_ERROR", "message": str(exc)})
        finally:
            _put_event("done")

    Thread(target=_runner, daemon=True).start()

    def _event_stream():
        while True:
            try:
                event = event_queue.get(timeout=30)
            except Empty:
                yield "data: {\"type\":\"heartbeat\"}\n\n"
                continue
            yield f"data: {json.dumps(event)}\n\n"
            if event.get("type") == "done":
                break

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ── Sandbox ────────────────────────────────────────────────────────────────────

@router.post("/sandbox/simulate", response_model=ApiResponse)
def sandbox_simulate(payload: SandboxSimulateRequest) -> ApiResponse:
    request_id = str(uuid4())
    start_time = perf_counter()
    try:
        event = simulate_sandbox_event(
            scenario=payload.scenario,
            vulnerable_mode=payload.vulnerable_mode,
            source_ip=payload.source_ip,
            append_to_log=payload.append_to_live_log,
        )
        return _build_success_response(
            request_id=request_id,
            mode=None,
            model=None,
            result=event,
            trace=[],
            start_time=start_time,
            endpoint="/api/v1/sandbox/simulate",
            input_text=json.dumps(payload.model_dump(), ensure_ascii=True),
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/sandbox/scenarios", response_model=ApiResponse)
def sandbox_scenarios() -> ApiResponse:
    request_id = str(uuid4())
    start_time = perf_counter()
    try:
        scenarios = get_sandbox_scenarios()
        return _build_success_response(
            request_id=request_id,
            mode=None,
            model=None,
            result=scenarios,
            trace=[],
            start_time=start_time,
            endpoint="/api/v1/sandbox/scenarios",
            input_text="",
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/sandbox/analyze", response_model=ApiResponse)
def sandbox_analyze(payload: SandboxAnalyzeRequest) -> ApiResponse:
    request_id = str(uuid4())
    start_time = perf_counter()
    try:
        result, trace, model, stop_reason, steps_used, prompt_version, rubric_score, rubric_label = (
            _normalize_analysis_result(
            analyze_sandbox_event(
                event=payload.event,
                mode=payload.mode,
                session_id=payload.session_id,
            )
        )
        )
        return _build_success_response(
            request_id=request_id,
            mode=payload.mode,
            model=model,
            result=result,
            trace=trace if payload.include_trace else [],
            start_time=start_time,
            stop_reason=stop_reason,
            steps_used=steps_used,
            prompt_version=prompt_version,
            rubric_score=rubric_score,
            rubric_label=rubric_label,
            endpoint="/api/v1/sandbox/analyze",
            input_text=json.dumps(payload.event, ensure_ascii=True),
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/sandbox/live-log", response_model=ApiResponse)
def sandbox_live_log(
    tail: int = Query(default=50, ge=1, le=200),
    source: str = Query(default="live_web_logs"),
) -> ApiResponse:
    request_id = str(uuid4())
    source_map = {
        "live_web_logs": Settings.LOGS_DIR / "live_web_logs.jsonl",
        "vuln_lab_events": Settings.LOGS_DIR / "vuln_lab_events.jsonl",
        "vuln_lab_detections": Settings.LOGS_DIR / "vuln_lab_detections.jsonl",
    }
    if source not in source_map:
        raise HTTPException(status_code=400, detail=f"Unknown source '{source}'.")
    path = source_map[source]
    return ApiResponse(
        ok=True,
        result={
            "source": source,
            "path": str(path),
            "items": _tail_jsonl(path, tail),
        },
        trace=[],
        meta=ResponseMeta(request_id=request_id, run_id=request_id, mode=None, model=None, duration_ms=0),
        error=None,
    )
