"""Typed API contracts for FastAPI endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class ErrorInfo(BaseModel):
    """Standardized API error payload."""

    code: str
    message: str
    details: Optional[Dict[str, Any]] = None


class ResponseMeta(BaseModel):
    """Metadata attached to all API responses."""

    request_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    api_version: Literal["v1"] = "v1"
    mode: Optional[Literal["g1", "g2"]] = None
    model: Optional[str] = None
    duration_ms: Optional[int] = None


class StepTrace(BaseModel):
    """Human-readable execution trace step."""

    step: str
    what_it_does: str
    prompt_preview: str
    input_summary: str
    output_summary: str


class AnalyzeRequest(BaseModel):
    """Request for G1/G2 analysis endpoints."""

    input: str = Field(min_length=1, max_length=50_000)
    session_id: Optional[str] = None
    include_trace: bool = True


class ChatRequest(BaseModel):
    """Request for chat endpoint."""

    input: str = Field(min_length=1, max_length=50_000)
    mode: Literal["g1", "g2"] = "g1"
    session_id: Optional[str] = None
    include_trace: bool = True


class SandboxSimulateRequest(BaseModel):
    """Request to generate a sandbox event."""

    scenario: str
    vulnerable_mode: bool = False
    source_ip: str = "127.0.0.1"
    append_to_live_log: bool = True


class SandboxAnalyzeRequest(BaseModel):
    """Request to analyze a sandbox event."""

    event: Dict[str, Any]
    mode: Literal["g1", "g2"] = "g1"
    session_id: Optional[str] = None
    include_trace: bool = True


class ApiResponse(BaseModel):
    """Unified response envelope used by all endpoints."""

    ok: bool
    result: Any = None
    trace: List[StepTrace] = Field(default_factory=list)
    meta: ResponseMeta
    error: Optional[ErrorInfo] = None
