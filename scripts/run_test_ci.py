#!/usr/bin/env python3
"""Run pytest for CI: excludes flaky, key-gated, or legacy integration tests.

When adding a path to IGNORED, add a comment on the preceding line (owner + reason)
and document the follow-up in the PR description.
"""

from __future__ import annotations

import sys

import pytest

IGNORED = [
    # G2 multiagent — stabilize imports/graph in CI before restoring.
    "tests/unit/test_multiagent.py",
    # RAG — Pinecone + embeddings; mock-heavy; run locally or in keyed CI.
    "tests/unit/test_rag_tools.py",
    # G1 service — tighter coupling; restore when CI deps align.
    "tests/unit/test_g1_service.py",
    # Tools — OTX + filesystem; run locally with keys/mocks as needed.
    "tests/unit/test_tools.py",
    # Integration — requires OPENAI_API_KEY; manual / pre-release.
    "tests/integration/test_agent_flow.py",
]


def main() -> int:
    args = ["-q", *[f"--ignore={path}" for path in IGNORED], *sys.argv[1:]]
    return pytest.main(args)


if __name__ == "__main__":
    raise SystemExit(main())
