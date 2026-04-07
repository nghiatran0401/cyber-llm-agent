"""Centralized configuration management."""
import os
from pathlib import Path

from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Settings:
    """Application settings loaded from environment variables."""

    # API Keys
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

    # Model Configuration
    FAST_MODEL_NAME = os.getenv("FAST_MODEL_NAME", "gpt-4o-mini")
    STRONG_MODEL_NAME = os.getenv("STRONG_MODEL_NAME", "gpt-4o")
    TEMPERATURE = float(os.getenv("TEMPERATURE", "0.5"))
    MAX_TOKENS = int(os.getenv("MAX_TOKENS", "2000"))

    ALLOWED_LOG_EXTENSIONS = {".txt", ".log", ".json", ".jsonl"}

    MAX_AGENT_STEPS = int(os.getenv("MAX_AGENT_STEPS", "12"))
    MAX_TOOL_CALLS = int(os.getenv("MAX_TOOL_CALLS", "8"))
    MAX_RUNTIME_SECONDS = int(os.getenv("MAX_RUNTIME_SECONDS", "60"))
    MAX_WORKER_TASKS = int(os.getenv("MAX_WORKER_TASKS", "4"))
    PROMPT_VERSION_G1 = os.getenv("PROMPT_VERSION_G1", "security_analysis_v2.txt")
    PROMPT_VERSION_G2 = os.getenv("PROMPT_VERSION_G2", "security_analysis_v2.txt")
    ENABLE_RUBRIC_EVAL = os.getenv("ENABLE_RUBRIC_EVAL", "true").lower() == "true"
    ENABLE_OUTPUT_POLICY_GUARD = os.getenv("ENABLE_OUTPUT_POLICY_GUARD", "true").lower() == "true"
    REQUIRE_HUMAN_APPROVAL_HIGH_RISK = os.getenv("REQUIRE_HUMAN_APPROVAL_HIGH_RISK", "false").lower() == "true"
    MIN_EVIDENCE_FOR_HIGH_RISK = int(os.getenv("MIN_EVIDENCE_FOR_HIGH_RISK", "1"))

    # CTI — API key only; OTX URL and limits are fixed in src/tools/cti_tool.py
    OTX_API_KEY = os.getenv("OTX_API_KEY", "")

    # RAG — Pinecone + OpenAI embeddings over data/knowledge
    ENABLE_RAG = os.getenv("ENABLE_RAG", "true").lower() == "true"
    RAG_MAX_RESULTS = int(os.getenv("RAG_MAX_RESULTS", "3"))
    PINECONE_API_KEY = os.getenv("PINECONE_API_KEY", "")
    PINECONE_INDEX_NAME = os.getenv("PINECONE_INDEX_NAME", "cyber-llm-knowledge")

    # Memory recall embeddings (OpenAI; uses OPENAI_API_KEY)
    OPENAI_EMBEDDING_MODEL = os.getenv("OPENAI_EMBEDDING_MODEL", "text-embedding-3-small")

    # Paths
    BASE_DIR = Path(__file__).parent.parent.parent
    DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
    LOGS_DIR = Path(os.getenv("LOGS_DIR", DATA_DIR / "logs"))
    SESSIONS_DIR = Path(os.getenv("SESSIONS_DIR", DATA_DIR / "sessions"))
    BENCHMARKS_DIR = DATA_DIR / "benchmarks"
    KNOWLEDGE_DIR = Path(os.getenv("KNOWLEDGE_DIR", DATA_DIR / "knowledge"))

    # Ensure directories exist
    @classmethod
    def ensure_directories(cls):
        """Create necessary directories if they don't exist."""
        cls.DATA_DIR.mkdir(exist_ok=True)
        cls.LOGS_DIR.mkdir(exist_ok=True)
        cls.SESSIONS_DIR.mkdir(exist_ok=True)
        cls.BENCHMARKS_DIR.mkdir(exist_ok=True)
        cls.KNOWLEDGE_DIR.mkdir(exist_ok=True)
    
    @classmethod
    def validate(cls):
        """Validate that required settings are present."""
        if not cls.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY is required. Set it in .env file.")
        if not cls.FAST_MODEL_NAME or not cls.STRONG_MODEL_NAME:
            raise ValueError("FAST_MODEL_NAME and STRONG_MODEL_NAME must be configured.")
        if not (0.0 <= cls.TEMPERATURE <= 1.0):
            raise ValueError("TEMPERATURE must be between 0.0 and 1.0.")
        if cls.MAX_TOKENS <= 0:
            raise ValueError("MAX_TOKENS must be greater than 0.")
        if not cls.OTX_API_KEY:
            raise ValueError("OTX_API_KEY is required.")
        if cls.MAX_AGENT_STEPS <= 0:
            raise ValueError("MAX_AGENT_STEPS must be greater than 0.")
        if cls.MAX_TOOL_CALLS <= 0:
            raise ValueError("MAX_TOOL_CALLS must be greater than 0.")
        if cls.MAX_RUNTIME_SECONDS <= 0:
            raise ValueError("MAX_RUNTIME_SECONDS must be greater than 0.")
        if cls.MAX_WORKER_TASKS <= 0:
            raise ValueError("MAX_WORKER_TASKS must be greater than 0.")
        if not cls.PROMPT_VERSION_G1.strip():
            raise ValueError("PROMPT_VERSION_G1 must not be empty.")
        if not cls.PROMPT_VERSION_G2.strip():
            raise ValueError("PROMPT_VERSION_G2 must not be empty.")
        if cls.ENABLE_RAG:
            if not cls.PINECONE_API_KEY:
                raise ValueError("PINECONE_API_KEY is required when ENABLE_RAG=true.")
            if not cls.PINECONE_INDEX_NAME:
                raise ValueError("PINECONE_INDEX_NAME is required when ENABLE_RAG=true.")
        if cls.RAG_MAX_RESULTS <= 0:
            raise ValueError("RAG_MAX_RESULTS must be greater than 0.")
        return True

    @classmethod
    def is_high_risk_task(cls, user_text: str) -> bool:
        """Return whether the input is high risk using semantic intent routing."""
        try:
            from src.agents.shared.intent_routing import is_high_risk_intent

            return bool(is_high_risk_intent(user_text))
        except Exception:
            # Keep API execution resilient if router dependencies fail to import.
            return False

    @classmethod
    def should_use_strong_model(cls, user_text: str) -> bool:
        """Use strong model for high-risk tasks (intent-based routing is always on)."""
        return cls.is_high_risk_task(user_text)


# Initialize directories on import
Settings.ensure_directories()

