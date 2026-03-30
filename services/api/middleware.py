"""HTTP middleware: authentication, rate limiting, and exception handlers."""

from __future__ import annotations

import json
from collections import defaultdict, deque
from threading import Lock
from time import perf_counter
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.config.settings import Settings

from .metrics import record_metric
from .schemas import ApiResponse, ErrorInfo, ResponseMeta

_RATE_BUCKETS: dict[str, deque[float]] = defaultdict(deque)
_RATE_LOCK = Lock()


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


def register_middleware(app: FastAPI) -> None:
    """Attach CORS, auth, rate-limit, and exception handlers to the app."""
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def request_guardrails(request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/v1") and path != "/api/v1/health":
            if Settings.API_AUTH_ENABLED:
                provided = request.headers.get("x-api-key", "")
                if provided != Settings.API_AUTH_KEY:
                    from .metrics import increment_auth_fail
                    increment_auth_fail()
                    record_metric(
                        endpoint=path,
                        duration_ms=0,
                        success=False,
                        mode=None,
                        stop_reason="error",
                    )
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
                    from .metrics import increment_rate_limited
                    increment_rate_limited()
                    record_metric(
                        endpoint=path,
                        duration_ms=0,
                        success=False,
                        mode=None,
                        stop_reason="budget_exceeded",
                    )
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

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(_, exc: Exception):
        from fastapi import HTTPException
        if isinstance(exc, HTTPException):
            return await http_exception_handler(_, exc)
        request_id = str(uuid4())
        response = ApiResponse(
            ok=False,
            result=None,
            trace=[],
            meta=ResponseMeta(request_id=request_id, mode=None, model=None, duration_ms=None),
            error=ErrorInfo(code="HTTP_500", message="Internal server error."),
        )
        record_metric(
            endpoint="unhandled",
            duration_ms=0,
            success=False,
            mode=None,
            stop_reason="error",
        )
        return JSONResponse(status_code=500, content=response.model_dump())


async def http_exception_handler(_, exc):
    """Handle HTTPException with standard envelope."""
    from fastapi import HTTPException
    request_id = str(uuid4())
    response = ApiResponse(
        ok=False,
        result=None,
        trace=[],
        meta=ResponseMeta(request_id=request_id, mode=None, model=None, duration_ms=None),
        error=ErrorInfo(code=f"HTTP_{exc.status_code}", message=str(exc.detail)),
    )
    record_metric(
        endpoint=f"http_{exc.status_code}",
        duration_ms=0,
        success=False,
        mode=None,
        stop_reason="error",
    )
    return JSONResponse(status_code=exc.status_code, content=response.model_dump())
