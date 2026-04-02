"""HTTP middleware: CORS and exception handlers."""

from __future__ import annotations

from uuid import uuid4

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .metrics import record_metric
from .schemas import ApiResponse, ErrorInfo, ResponseMeta


def register_middleware(app: FastAPI) -> None:
    """Attach CORS and exception handlers to the app."""
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

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
