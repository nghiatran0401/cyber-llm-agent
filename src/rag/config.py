import os
from dataclasses import dataclass
from dotenv import load_dotenv


load_dotenv()


@dataclass
class Settings:
    """Central configuration for the RAG system."""

    # Paths
    data_path: str = os.getenv("RAG_DATA_PATH", "data/mitre")
    chroma_path: str = os.getenv("RAG_CHROMA_PATH", "data/chroma_db")

    # Chroma / embeddings
    chroma_collection: str = os.getenv("RAG_CHROMA_COLLECTION", "mitre_attack")
    embedding_model: str = os.getenv("RAG_EMBEDDING_MODEL", "all-MiniLM-L6-v2")

    # Retrieval
    top_k: int = int(os.getenv("RAG_TOP_K", "8"))
    distance_threshold: float = float(os.getenv("RAG_DISTANCE_THRESHOLD", "0.7"))

    # LLM / OpenRouter
    openrouter_api_key: str = os.getenv("OPENROUTER_API_KEY", "")
    openrouter_base_url: str = os.getenv(
        "OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"
    )
    mitre_model: str = os.getenv(
        "RAG_MITRE_MODEL", "nvidia/nemotron-3-nano-30b-a3b:free"
    )

    # OTX / IOC extraction
    otx_timeout_seconds: int = int(os.getenv("RAG_OTX_TIMEOUT_SECONDS", "15"))
    max_otx_iocs: int = int(os.getenv("RAG_MAX_OTX_IOCS", "5"))

    # Logging
    log_level: str = os.getenv("RAG_LOG_LEVEL", "INFO")


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return a singleton Settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings

