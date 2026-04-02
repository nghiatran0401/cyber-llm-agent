"""FastAPI entrypoint for cyber-llm-agent HTTP API.

This module is a thin shell. Business logic lives in:
  - routes.py      → All route handlers
  - middleware.py   → CORS, exception handlers
  - metrics.py      → In-memory metrics aggregation
  - schemas.py      → Pydantic request/response contracts
  - g1_service.py   → G1 single-agent runner
  - g2_service.py   → G2 multi-agent runner
  - guardrails.py   → Input/output security guardrails
  - response_parser.py → Structured report building
  - sandbox_service.py → Sandbox event simulation/analysis
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from src.config.settings import Settings

from .middleware import register_middleware, http_exception_handler
from .routes import router


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    Settings.validate()
    yield


app = FastAPI(
    title="Cyber LLM Agent API",
    version="0.1.0",
    description="HTTP API wrapper for G1/G2 cybersecurity agent workflows.",
    lifespan=_lifespan,
)

register_middleware(app)
app.include_router(router)

# Re-register HTTPException handler after router inclusion
from fastapi import HTTPException

app.add_exception_handler(HTTPException, http_exception_handler)
