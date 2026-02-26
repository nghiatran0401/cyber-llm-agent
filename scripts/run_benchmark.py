"""Backward-compatible CLI shim for benchmark runner."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure repository root is importable when executed as a script.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.benchmarking.agents import (
    OfflineDeterministicAgent as _OfflineDeterministicAgent,
)
from src.benchmarking.agents import RealLLMBenchmarkAgent as _RealLLMBenchmarkAgent
from src.benchmarking.reporting import load_latest_report as _load_latest_report
from src.benchmarking.reporting import render_markdown as _render_markdown
from src.benchmarking.reporting import write_artifacts as _write_artifacts
from src.benchmarking.runner import build_prompt as _build_prompt
from src.benchmarking.runner import load_dataset as _load_dataset
from src.benchmarking.runner import main
from src.benchmarking.runner import normalize_cases as _normalize_cases
from src.benchmarking.runner import parse_args as _parse_args


if __name__ == "__main__":
    raise SystemExit(main())
