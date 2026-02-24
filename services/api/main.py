"""FastAPI entrypoint for cyber-llm-agent HTTP API."""

from __future__ import annotations

import json
import os
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from queue import Empty, Queue
from threading import Lock
from threading import Thread
from time import perf_counter
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from src.config.settings import Settings
from src.utils.logger import setup_logger, log_structured

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
from .service import (
    analyze_sandbox_event,
    get_sandbox_scenarios,
    run_chat,
    run_g1_analysis,
    run_g2_analysis,
    run_workspace_with_progress,
    simulate_sandbox_event,
)

@asynccontextmanager
async def _lifespan(_app: FastAPI):
    if Settings.VALIDATE_ON_STARTUP and "PYTEST_CURRENT_TEST" not in os.environ:
        Settings.validate()
    yield


app = FastAPI(
    title="Cyber LLM Agent API",
    version="0.1.0",
    description="HTTP API wrapper for G1/G2 cybersecurity agent workflows.",
    lifespan=_lifespan,
)

_RATE_BUCKETS: dict[str, deque[float]] = defaultdict(deque)
_RATE_LOCK = Lock()
_METRICS_LOCK = Lock()
_METRICS_STATE = {
    "requests_total": 0,
    "success_total": 0,
    "error_total": 0,
    "auth_fail_total": 0,
    "rate_limited_total": 0,
    "duration_total_ms": 0,
    "by_endpoint": defaultdict(int),
}
logger = setup_logger(__name__)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _require_sandbox_enabled() -> None:
    if not Settings.sandbox_enabled():
        raise HTTPException(status_code=403, detail="Sandbox is disabled for this environment.")


def _check_rate_limit(client_key: str) -> tuple[bool, int]:
    now = perf_counter()
    window = Settings.API_RATE_LIMIT_WINDOW_SECONDS
    max_requests = Settings.API_RATE_LIMIT_MAX_REQUESTS
    with _RATE_LOCK:
        bucket = _RATE_BUCKETS[client_key]
        while bucket and (now - bucket[0]) > window:
            bucket.popleft()
        if len(bucket) >= max_requests:
            retry_after = int(window - (now - bucket[0])) if bucket else window
            return False, max(1, retry_after)
        bucket.append(now)
    return True, 0


def _estimate_tokens(text: str) -> int:
    content = str(text or "")
    if not content.strip():
        return 0
    return max(1, len(content) // 4)


def _extract_text_payload(value) -> str:
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=True)
    return str(value or "")


def _derive_tool_stats(result, trace) -> tuple[int, int, int]:
    statuses: dict[str, bool] = {}
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

    for item in trace or []:
        step_name = item.get("step") if isinstance(item, dict) else getattr(item, "step", "")
        if step_name == "WorkerTask":
            statuses.setdefault("WorkerTask", True)

    tool_calls = len(statuses)
    tool_success = sum(1 for ok in statuses.values() if ok)
    tool_fail = max(0, tool_calls - tool_success)
    return tool_calls, tool_success, tool_fail


def _enrich_trace(trace, run_id: str):
    enriched: list[StepTrace] = []
    for idx, item in enumerate(trace or [], start=1):
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
        payload["step_id"] = payload.get("step_id") or f"{run_id}-s{idx:03d}"
        if payload.get("step") in {"WorkerTask", "SingleAgentExecution", "LogAnalyzer", "ThreatPredictor"}:
            payload["tool_call_id"] = payload.get("tool_call_id") or f"{run_id}-t{idx:03d}"
        enriched.append(StepTrace(**payload))
    return enriched


def _record_metric(endpoint: str, duration_ms: int, success: bool):
    with _METRICS_LOCK:
        _METRICS_STATE["requests_total"] += 1
        _METRICS_STATE["duration_total_ms"] += max(0, int(duration_ms))
        _METRICS_STATE["by_endpoint"][endpoint] += 1
        if success:
            _METRICS_STATE["success_total"] += 1
        else:
            _METRICS_STATE["error_total"] += 1


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
    tool_calls, tool_success, tool_fail = _derive_tool_stats(result=result, trace=enriched_trace)

    if endpoint:
        _record_metric(endpoint=endpoint, duration_ms=duration_ms, success=True)
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


@app.get("/api/v1/health", response_model=ApiResponse)
def health() -> ApiResponse:
    request_id = str(uuid4())
    return ApiResponse(
        ok=True,
        result={
            "status": "healthy",
            "environment": Settings.ENVIRONMENT,
            "sandbox_enabled": Settings.sandbox_enabled(),
        },
        trace=[],
        meta=ResponseMeta(request_id=request_id, mode=None, model=None, duration_ms=0),
        error=None,
    )


@app.middleware("http")
async def request_guardrails(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/v1") and path != "/api/v1/health":
        if Settings.API_AUTH_ENABLED:
            provided = request.headers.get("x-api-key", "")
            if provided != Settings.API_AUTH_KEY:
                with _METRICS_LOCK:
                    _METRICS_STATE["auth_fail_total"] += 1
                response = ApiResponse(
                    ok=False,
                    result=None,
                    trace=[],
                    meta=ResponseMeta(request_id=str(uuid4()), mode=None, model=None, duration_ms=None),
                    error=ErrorInfo(code="HTTP_401", message="Unauthorized: invalid API key."),
                )
                return JSONResponse(status_code=401, content=response.model_dump())
        if Settings.API_RATE_LIMIT_ENABLED:
            client_key = (
                request.headers.get("x-api-key") or (request.client.host if request.client else "unknown")
            )
            allowed, retry_after = _check_rate_limit(client_key=client_key)
            if not allowed:
                with _METRICS_LOCK:
                    _METRICS_STATE["rate_limited_total"] += 1
                response = ApiResponse(
                    ok=False,
                    result=None,
                    trace=[],
                    meta=ResponseMeta(request_id=str(uuid4()), mode=None, model=None, duration_ms=None),
                    error=ErrorInfo(code="HTTP_429", message="Rate limit exceeded. Try again shortly."),
                )
                return JSONResponse(
                    status_code=429,
                    content=response.model_dump(),
                    headers={"Retry-After": str(retry_after)},
                )
    return await call_next(request)


@app.get("/api/v1/ready", response_model=ApiResponse)
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


@app.get("/api/v1/metrics", response_model=ApiResponse)
def metrics() -> ApiResponse:
    request_id = str(uuid4())
    with _METRICS_LOCK:
        requests_total = int(_METRICS_STATE["requests_total"])
        success_total = int(_METRICS_STATE["success_total"])
        error_total = int(_METRICS_STATE["error_total"])
        auth_fail_total = int(_METRICS_STATE["auth_fail_total"])
        rate_limited_total = int(_METRICS_STATE["rate_limited_total"])
        duration_total_ms = int(_METRICS_STATE["duration_total_ms"])
        by_endpoint = dict(_METRICS_STATE["by_endpoint"])
    avg_duration_ms = round(duration_total_ms / requests_total, 2) if requests_total else 0.0
    return ApiResponse(
        ok=True,
        result={
            "requests_total": requests_total,
            "success_total": success_total,
            "error_total": error_total,
            "auth_fail_total": auth_fail_total,
            "rate_limited_total": rate_limited_total,
            "avg_duration_ms": avg_duration_ms,
            "by_endpoint": by_endpoint,
        },
        trace=[],
        meta=ResponseMeta(request_id=request_id, run_id=request_id, mode=None, model=None, duration_ms=0),
        error=None,
    )


@app.post("/api/v1/analyze/g1", response_model=ApiResponse)
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


@app.post("/api/v1/analyze/g2", response_model=ApiResponse)
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


@app.post("/api/v1/chat", response_model=ApiResponse)
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


@app.post("/api/v1/workspace/stream")
def workspace_stream(payload: WorkspaceStreamRequest):
    """Stream progress events for workspace requests (SSE)."""
    request_id = str(uuid4())
    event_queue: Queue[dict] = Queue()
    start_time = perf_counter()
    def _put_event(event_type: str, **data):
        event_queue.put({"type": event_type, **data})

    def _runner():
        try:
            def _on_step(step: StepTrace):
                _put_event("trace", step=step.model_dump())

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
            run_id = request_id
            input_tokens_est = _estimate_tokens(payload.input)
            output_tokens_est = _estimate_tokens(_extract_text_payload(result))
            total_tokens_est = input_tokens_est + output_tokens_est
            cost_est_usd = round((total_tokens_est / 1000) * 0.0005, 6)
            tool_calls, tool_success, tool_fail = _derive_tool_stats(result=result, trace=[])
            _record_metric(endpoint="/api/v1/workspace/stream", duration_ms=duration_ms, success=True)
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


@app.post("/api/v1/sandbox/simulate", response_model=ApiResponse)
def sandbox_simulate(payload: SandboxSimulateRequest) -> ApiResponse:
    request_id = str(uuid4())
    start_time = perf_counter()
    try:
        _require_sandbox_enabled()
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


@app.get("/api/v1/sandbox/scenarios", response_model=ApiResponse)
def sandbox_scenarios() -> ApiResponse:
    request_id = str(uuid4())
    start_time = perf_counter()
    try:
        _require_sandbox_enabled()
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


@app.post("/api/v1/sandbox/analyze", response_model=ApiResponse)
def sandbox_analyze(payload: SandboxAnalyzeRequest) -> ApiResponse:
    request_id = str(uuid4())
    start_time = perf_counter()
    try:
        _require_sandbox_enabled()
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


@app.exception_handler(HTTPException)
async def http_exception_handler(_, exc: HTTPException):
    request_id = str(uuid4())
    response = ApiResponse(
        ok=False,
        result=None,
        trace=[],
        meta=ResponseMeta(request_id=request_id, mode=None, model=None, duration_ms=None),
        error=ErrorInfo(code=f"HTTP_{exc.status_code}", message=str(exc.detail)),
    )
    _record_metric(endpoint=f"http_{exc.status_code}", duration_ms=0, success=False)
    return JSONResponse(status_code=exc.status_code, content=response.model_dump())


@app.exception_handler(Exception)
async def unhandled_exception_handler(_, exc: Exception):
    request_id = str(uuid4())
    response = ApiResponse(
        ok=False,
        result=None,
        trace=[],
        meta=ResponseMeta(request_id=request_id, mode=None, model=None, duration_ms=None),
        error=ErrorInfo(code="HTTP_500", message="Internal server error."),
    )
    _record_metric(endpoint="unhandled", duration_ms=0, success=False)
    return JSONResponse(status_code=500, content=response.model_dump())
