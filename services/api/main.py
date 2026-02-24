"""FastAPI entrypoint for cyber-llm-agent HTTP API."""

from __future__ import annotations

import json
from queue import Empty, Queue
from threading import Thread
from time import perf_counter
from uuid import uuid4

from fastapi import FastAPI, HTTPException
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

app = FastAPI(
    title="Cyber LLM Agent API",
    version="0.1.0",
    description="HTTP API wrapper for G1/G2 cybersecurity agent workflows.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _build_success_response(
    request_id: str,
    mode: str | None,
    model: str | None,
    result,
    trace,
    start_time: float,
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
        ),
        error=None,
    )


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


@app.post("/api/v1/analyze/g1", response_model=ApiResponse)
def analyze_g1(payload: AnalyzeRequest) -> ApiResponse:
    request_id = str(uuid4())
    start_time = perf_counter()
    try:
        response, trace, model = run_g1_analysis(payload.input, session_id=payload.session_id)
        return _build_success_response(
            request_id=request_id,
            mode="g1",
            model=model,
            result=response,
            trace=trace if payload.include_trace else [],
            start_time=start_time,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/analyze/g2", response_model=ApiResponse)
def analyze_g2(payload: AnalyzeRequest) -> ApiResponse:
    request_id = str(uuid4())
    start_time = perf_counter()
    try:
        result, trace, model = run_g2_analysis(payload.input)
        return _build_success_response(
            request_id=request_id,
            mode="g2",
            model=model,
            result=result,
            trace=trace if payload.include_trace else [],
            start_time=start_time,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/chat", response_model=ApiResponse)
def chat(payload: ChatRequest) -> ApiResponse:
    request_id = str(uuid4())
    start_time = perf_counter()
    try:
        response, trace, model = run_chat(payload.input, mode=payload.mode, session_id=payload.session_id)
        return _build_success_response(
            request_id=request_id,
            mode=payload.mode,
            model=model,
            result=response,
            trace=trace if payload.include_trace else [],
            start_time=start_time,
        )
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

            result, model = run_workspace_with_progress(
                task=payload.task,
                mode=payload.mode,
                user_input=payload.input,
                on_step=_on_step,
                session_id=payload.session_id,
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
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/sandbox/scenarios", response_model=ApiResponse)
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
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/sandbox/analyze", response_model=ApiResponse)
def sandbox_analyze(payload: SandboxAnalyzeRequest) -> ApiResponse:
    request_id = str(uuid4())
    start_time = perf_counter()
    try:
        result, trace, model = analyze_sandbox_event(
            event=payload.event,
            mode=payload.mode,
            session_id=payload.session_id,
        )
        return _build_success_response(
            request_id=request_id,
            mode=payload.mode,
            model=model,
            result=result,
            trace=trace if payload.include_trace else [],
            start_time=start_time,
        )
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
