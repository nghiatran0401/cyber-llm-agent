#!/usr/bin/env python3
"""Stable CLI entry for benchmarks (used by Makefile).

When to use:
- `make benchmark` for keyed benchmark runs.
- `make benchmark-report` to render latest markdown summary.
"""

from __future__ import annotations

import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
# Load repo .env before any src imports so Settings sees keys regardless of cwd.
load_dotenv(ROOT / ".env")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.benchmarking.runner import main

if __name__ == "__main__":
    raise SystemExit(main())
