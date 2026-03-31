"""Standalone RAG subsystem configuration (Chroma + local MITRE markdown).

Env vars are read when ``get_settings()`` first runs (and after each cache reset)
via ``default_factory``, so paths can be aligned with ``src.config.settings``
before building or querying the index.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Settings:
    """Central configuration for the optional local MITRE / Chroma RAG stack."""

    data_path: str = field(default_factory=lambda: os.getenv("RAG_DATA_PATH", "data/mitre"))
    chroma_path: str = field(default_factory=lambda: os.getenv("RAG_CHROMA_PATH", "data/chroma_db"))
    chroma_collection: str = field(
        default_factory=lambda: os.getenv("RAG_CHROMA_COLLECTION", "mitre_attack")
    )
    embedding_model: str = field(
        default_factory=lambda: os.getenv("RAG_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
    )
    top_k: int = field(default_factory=lambda: int(os.getenv("RAG_TOP_K", "8")))
    distance_threshold: float = field(
        default_factory=lambda: float(os.getenv("RAG_DISTANCE_THRESHOLD", "0.7"))
    )
    openrouter_api_key: str = field(default_factory=lambda: os.getenv("OPENROUTER_API_KEY", ""))
    openrouter_base_url: str = field(
        default_factory=lambda: os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    )
    mitre_model: str = field(
        default_factory=lambda: os.getenv("RAG_MITRE_MODEL", "nvidia/nemotron-3-nano-30b-a3b:free")
    )
    otx_timeout_seconds: int = field(
        default_factory=lambda: int(os.getenv("RAG_OTX_TIMEOUT_SECONDS", "15"))
    )
    max_otx_iocs: int = field(default_factory=lambda: int(os.getenv("RAG_MAX_OTX_IOCS", "5")))
    log_level: str = field(default_factory=lambda: os.getenv("RAG_LOG_LEVEL", "INFO"))


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return a cached Settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_rag_config_cache() -> None:
    """Clear cached settings (e.g. after syncing env from app Settings)."""
    global _settings
    _settings = None
