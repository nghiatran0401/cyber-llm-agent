#!/usr/bin/env python3
"""Run pytest for CI against core product workflows only.

When to use:
- In CI (`make test-ci`) to enforce required coverage.
- Locally before opening a PR to mirror CI Python checks.
"""

from __future__ import annotations

import sys

import pytest

CORE_WORKFLOW_TESTS = [
    "tests/unit/test_api_endpoints.py",
    "tests/unit/test_guardrails.py",
    "tests/unit/test_agent_loop_runtime.py",
    "tests/unit/test_g1_service.py",
    "tests/unit/test_g2_service.py",
    "tests/unit/test_g2_runner.py",
    "tests/unit/test_tools.py",
    "tests/unit/test_rag_tools.py",
    "tests/unit/test_memory.py",
    "tests/unit/test_intent_routing.py",
    "tests/unit/test_sandbox.py",
]


def main() -> int:
    args = ["-q", *CORE_WORKFLOW_TESTS, *sys.argv[1:]]
    return pytest.main(args)


if __name__ == "__main__":
    raise SystemExit(main())
