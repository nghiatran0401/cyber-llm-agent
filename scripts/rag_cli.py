#!/usr/bin/env python3
"""Interactive CLI for the standalone RAG agent flows (MITRE + OTX).

Run from repository root:

    python3 scripts/rag_cli.py

Requires a built Chroma index (``python3 scripts/rag_build_index.py``) and
appropriate ``.env`` / OpenRouter settings for LLM-backed agents.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def main() -> None:
    from src.rag.cli.main import main as rag_main

    rag_main()


if __name__ == "__main__":
    main()
