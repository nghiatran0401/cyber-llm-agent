#!/usr/bin/env python3
"""Run pytest for CI: excludes flaky, key-gated, or legacy integration tests."""

from __future__ import annotations

import sys

import pytest

IGNORED = [
    "tests/unit/test_multiagent.py",
    "tests/unit/test_rag_tools.py",
    "tests/unit/test_g1_service.py",
    "tests/unit/test_tools.py",
    "tests/integration/test_agent_flow.py",
]


def main() -> int:
    args = ["-q", *[f"--ignore={path}" for path in IGNORED], *sys.argv[1:]]
    return pytest.main(args)


if __name__ == "__main__":
    raise SystemExit(main())
