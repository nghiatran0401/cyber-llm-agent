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


def _build_success_response(
    request_id: str,
    mode: str | None,
    model: str | None,
    result,
    trace,
    start_time: float,
    stop_reason: str | None = None,
    steps_used: int | None = None,
) -> ApiResponse:
    duration_ms = int((perf_counter() - start_time) * 1000)
    return ApiResponse(
        ok=True,
        result=result,
        trace=trace,
        meta=ResponseMeta(
            request_id=request_id,
            mode=mode,
            model=model,
            duration_ms=duration_ms,
            stop_reason=stop_reason,
            steps_used=steps_used,
        ),
        error=None,
    )


def _normalize_analysis_result(payload, fallback_steps: int = 1):
    """Support both old and new service return tuple shapes."""
    if isinstance(payload, tuple):
        if len(payload) == 5:
            return payload
        if len(payload) == 3:
            result, trace, model = payload
            steps = len(trace) if isinstance(trace, list) and trace else fallback_steps
            return result, trace, model, "completed", steps
    raise TypeError("Unexpected service response shape.")


def _normalize_workspace_result(payload):
    """Support both old and new workspace return tuple shapes."""
    if isinstance(payload, tuple):
        if len(payload) == 4:
            return payload
        if len(payload) == 2:
            result, model = payload
            return result, model, "completed", 1
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


@app.post("/api/v1/analyze/g1", response_model=ApiResponse)
def analyze_g1(payload: AnalyzeRequest) -> ApiResponse:
    request_id = str(uuid4())
    start_time = perf_counter()
    try:
        response, trace, model, stop_reason, steps_used = _normalize_analysis_result(
            run_g1_analysis(payload.input, session_id=payload.session_id)
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
        result, trace, model, stop_reason, steps_used = _normalize_analysis_result(run_g2_analysis(payload.input))
        return _build_success_response(
            request_id=request_id,
            mode="g2",
            model=model,
            result=result,
            trace=trace if payload.include_trace else [],
            start_time=start_time,
            stop_reason=stop_reason,
            steps_used=steps_used,
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
        response, trace, model, stop_reason, steps_used = _normalize_analysis_result(
            run_chat(payload.input, mode=payload.mode, session_id=payload.session_id)
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

            result, model, stop_reason, steps_used = _normalize_workspace_result(
                run_workspace_with_progress(
                task=payload.task,
                mode=payload.mode,
                user_input=payload.input,
                on_step=_on_step,
                session_id=payload.session_id,
            )
            )

            duration_ms = int((perf_counter() - start_time) * 1000)
            _put_event(
                "final",
                result=result,
                meta=ResponseMeta(
                    request_id=request_id,
                    mode=payload.mode,
                    model=model,
                    duration_ms=duration_ms,
                    stop_reason=stop_reason,
                    steps_used=steps_used,
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
        result, trace, model, stop_reason, steps_used = _normalize_analysis_result(
            analyze_sandbox_event(
                event=payload.event,
                mode=payload.mode,
                session_id=payload.session_id,
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
    return JSONResponse(status_code=500, content=response.model_dump())
