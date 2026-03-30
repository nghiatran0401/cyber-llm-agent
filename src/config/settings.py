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

    # Environment
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    ENABLE_SANDBOX = os.getenv("ENABLE_SANDBOX", "false").lower() == "true"
    ALLOWED_LOG_EXTENSIONS = {".txt", ".log", ".json", ".jsonl"}

    # API security and startup controls
    API_AUTH_ENABLED = os.getenv("API_AUTH_ENABLED", "false").lower() == "true"
    API_AUTH_KEY = os.getenv("API_AUTH_KEY", "")
    API_RATE_LIMIT_ENABLED = os.getenv("API_RATE_LIMIT_ENABLED", "false").lower() == "true"
    API_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("API_RATE_LIMIT_WINDOW_SECONDS", "60"))
    API_RATE_LIMIT_MAX_REQUESTS = int(os.getenv("API_RATE_LIMIT_MAX_REQUESTS", "60"))
    VALIDATE_ON_STARTUP = os.getenv("VALIDATE_ON_STARTUP", "true").lower() == "true"
    AGENT_CACHE_TTL_SECONDS = int(os.getenv("AGENT_CACHE_TTL_SECONDS", "3600"))
    AGENT_CACHE_MAX_SIZE = int(os.getenv("AGENT_CACHE_MAX_SIZE", "100"))
    MAX_AGENT_STEPS = int(os.getenv("MAX_AGENT_STEPS", "12"))
    MAX_TOOL_CALLS = int(os.getenv("MAX_TOOL_CALLS", "8"))
    MAX_RUNTIME_SECONDS = int(os.getenv("MAX_RUNTIME_SECONDS", "60"))
    MAX_WORKER_TASKS = int(os.getenv("MAX_WORKER_TASKS", "4"))
    MEMORY_MAX_EPISODIC_ITEMS = int(os.getenv("MEMORY_MAX_EPISODIC_ITEMS", "30"))
    MEMORY_MAX_SEMANTIC_FACTS = int(os.getenv("MEMORY_MAX_SEMANTIC_FACTS", "80"))
    MEMORY_RECALL_TOP_K = int(os.getenv("MEMORY_RECALL_TOP_K", "3"))
    SESSION_RETENTION_DAYS = int(os.getenv("SESSION_RETENTION_DAYS", "30"))
    PROMPT_VERSION_G1 = os.getenv("PROMPT_VERSION_G1", "security_analysis_v2.txt")
    PROMPT_VERSION_G2 = os.getenv("PROMPT_VERSION_G2", "security_analysis_v2.txt")
    ENABLE_RUBRIC_EVAL = os.getenv("ENABLE_RUBRIC_EVAL", "true").lower() == "true"
    ENABLE_PROMPT_INJECTION_GUARD = os.getenv("ENABLE_PROMPT_INJECTION_GUARD", "true").lower() == "true"
    ENABLE_OUTPUT_POLICY_GUARD = os.getenv("ENABLE_OUTPUT_POLICY_GUARD", "true").lower() == "true"
    REQUIRE_HUMAN_APPROVAL_HIGH_RISK = os.getenv("REQUIRE_HUMAN_APPROVAL_HIGH_RISK", "false").lower() == "true"
    MIN_EVIDENCE_FOR_HIGH_RISK = int(os.getenv("MIN_EVIDENCE_FOR_HIGH_RISK", "1"))

    # CTI (AlienVault OTX)
    OTX_API_KEY = os.getenv("OTX_API_KEY", "")
    OTX_BASE_URL = os.getenv("OTX_BASE_URL", "https://otx.alienvault.com/api/v1").rstrip("/")
    CTI_PROVIDER = os.getenv("CTI_PROVIDER", "otx").strip().lower()
    CTI_REQUEST_TIMEOUT_SECONDS = int(os.getenv("CTI_REQUEST_TIMEOUT_SECONDS", "10"))
    CTI_MAX_RETRIES = int(os.getenv("CTI_MAX_RETRIES", "2"))
    CTI_RETRY_BACKOFF_SECONDS = float(os.getenv("CTI_RETRY_BACKOFF_SECONDS", "0.5"))
    CTI_MAX_RESPONSE_CHARS = int(os.getenv("CTI_MAX_RESPONSE_CHARS", "3000"))
    CTI_TOP_RESULTS = int(os.getenv("CTI_TOP_RESULTS", "5"))

    # RAG (LangChain + Pinecone) — always enabled; tune retrieval depth here if needed
    ENABLE_RAG = os.getenv("ENABLE_RAG", "true").lower() == "true"
    RAG_MAX_RESULTS = 3
    PINECONE_API_KEY = os.getenv("PINECONE_API_KEY", "")
    PINECONE_INDEX_NAME = os.getenv("PINECONE_INDEX_NAME", "cyber-llm-knowledge")

    # Embedding configuration
    EMBEDDING_PROVIDER = os.getenv("EMBEDDING_PROVIDER", "openai").lower()
    # openai: uses text-embedding-3-small via existing OPENAI_API_KEY
    # ollama: uses nomic-embed-text via local Ollama instance
    OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_EMBEDDING_MODEL = os.getenv("OLLAMA_EMBEDDING_MODEL", "nomic-embed-text")
    OPENAI_EMBEDDING_MODEL = os.getenv("OPENAI_EMBEDDING_MODEL", "text-embedding-3-small")
    EMBEDDING_ENABLED = os.getenv("EMBEDDING_ENABLED", "true").lower() == "true"

    # Paths
    BASE_DIR = Path(__file__).parent.parent.parent
    DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
    LOGS_DIR = Path(os.getenv("LOGS_DIR", DATA_DIR / "logs"))
    SESSIONS_DIR = Path(os.getenv("SESSIONS_DIR", DATA_DIR / "sessions"))
    BENCHMARKS_DIR = DATA_DIR / "benchmarks"
    CTI_FEEDS_DIR = DATA_DIR / "cti_feeds"
    KNOWLEDGE_DIR = Path(os.getenv("KNOWLEDGE_DIR", DATA_DIR / "knowledge"))
    
    # Ensure directories exist
    @classmethod
    def ensure_directories(cls):
        """Create necessary directories if they don't exist."""
        cls.DATA_DIR.mkdir(exist_ok=True)
        cls.LOGS_DIR.mkdir(exist_ok=True)
        cls.SESSIONS_DIR.mkdir(exist_ok=True)
        cls.BENCHMARKS_DIR.mkdir(exist_ok=True)
        cls.CTI_FEEDS_DIR.mkdir(exist_ok=True)
        cls.KNOWLEDGE_DIR.mkdir(exist_ok=True)
    
    @classmethod
    def validate(cls):
        """Validate that required settings are present."""
        allowed_envs = {"development", "staging", "production"}
        if cls.ENVIRONMENT not in allowed_envs:
            raise ValueError(
                f"ENVIRONMENT must be one of {sorted(allowed_envs)}; got '{cls.ENVIRONMENT}'."
            )
        if cls.ENVIRONMENT == "production" and cls.ENABLE_SANDBOX:
            raise ValueError("ENABLE_SANDBOX must be false when ENVIRONMENT=production.")
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
        if cls.CTI_PROVIDER != "otx":
            raise ValueError("CTI_PROVIDER must be 'otx'.")
        if cls.CTI_REQUEST_TIMEOUT_SECONDS <= 0:
            raise ValueError("CTI_REQUEST_TIMEOUT_SECONDS must be greater than 0.")
        if cls.CTI_MAX_RETRIES < 0:
            raise ValueError("CTI_MAX_RETRIES must be greater than or equal to 0.")
        if cls.CTI_RETRY_BACKOFF_SECONDS < 0:
            raise ValueError("CTI_RETRY_BACKOFF_SECONDS must be greater than or equal to 0.")
        if cls.CTI_MAX_RESPONSE_CHARS <= 0:
            raise ValueError("CTI_MAX_RESPONSE_CHARS must be greater than 0.")
        if cls.CTI_TOP_RESULTS <= 0:
            raise ValueError("CTI_TOP_RESULTS must be greater than 0.")
        if cls.API_RATE_LIMIT_WINDOW_SECONDS <= 0:
            raise ValueError("API_RATE_LIMIT_WINDOW_SECONDS must be greater than 0.")
        if cls.API_RATE_LIMIT_MAX_REQUESTS <= 0:
            raise ValueError("API_RATE_LIMIT_MAX_REQUESTS must be greater than 0.")
        if cls.API_AUTH_ENABLED and not cls.API_AUTH_KEY:
            raise ValueError("API_AUTH_KEY is required when API_AUTH_ENABLED=true.")
        if cls.AGENT_CACHE_TTL_SECONDS <= 0:
            raise ValueError("AGENT_CACHE_TTL_SECONDS must be greater than 0.")
        if cls.AGENT_CACHE_MAX_SIZE <= 0:
            raise ValueError("AGENT_CACHE_MAX_SIZE must be greater than 0.")
        if cls.MAX_AGENT_STEPS <= 0:
            raise ValueError("MAX_AGENT_STEPS must be greater than 0.")
        if cls.MAX_TOOL_CALLS <= 0:
            raise ValueError("MAX_TOOL_CALLS must be greater than 0.")
        if cls.MAX_RUNTIME_SECONDS <= 0:
            raise ValueError("MAX_RUNTIME_SECONDS must be greater than 0.")
        if cls.MAX_WORKER_TASKS <= 0:
            raise ValueError("MAX_WORKER_TASKS must be greater than 0.")
        if cls.MEMORY_MAX_EPISODIC_ITEMS <= 0:
            raise ValueError("MEMORY_MAX_EPISODIC_ITEMS must be greater than 0.")
        if cls.MEMORY_MAX_SEMANTIC_FACTS <= 0:
            raise ValueError("MEMORY_MAX_SEMANTIC_FACTS must be greater than 0.")
        if cls.MEMORY_RECALL_TOP_K <= 0:
            raise ValueError("MEMORY_RECALL_TOP_K must be greater than 0.")
        if cls.SESSION_RETENTION_DAYS <= 0:
            raise ValueError("SESSION_RETENTION_DAYS must be greater than 0.")
        if not cls.PROMPT_VERSION_G1.strip():
            raise ValueError("PROMPT_VERSION_G1 must not be empty.")
        if not cls.PROMPT_VERSION_G2.strip():
            raise ValueError("PROMPT_VERSION_G2 must not be empty.")
        if not cls.PINECONE_API_KEY:
            raise ValueError("PINECONE_API_KEY is required (RAG is always enabled).")
        if not cls.PINECONE_INDEX_NAME:
            raise ValueError("PINECONE_INDEX_NAME is required (RAG is always enabled).")
        if cls.RAG_MAX_RESULTS <= 0:
            raise ValueError("RAG_MAX_RESULTS must be greater than 0.")
        # Embedding validation
        allowed_embedding_providers = {"openai", "ollama"}
        if cls.EMBEDDING_PROVIDER not in allowed_embedding_providers:
            raise ValueError(
                f"EMBEDDING_PROVIDER must be one of {sorted(allowed_embedding_providers)}; "
                f"got '{cls.EMBEDDING_PROVIDER}'."
            )
        if cls.EMBEDDING_ENABLED and cls.EMBEDDING_PROVIDER == "openai" and not cls.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY is required when EMBEDDING_PROVIDER=openai.")
        if cls.EMBEDDING_ENABLED and cls.EMBEDDING_PROVIDER == "ollama" and not cls.OLLAMA_BASE_URL:
            raise ValueError("OLLAMA_BASE_URL is required when EMBEDDING_PROVIDER=ollama.")
        return True

    @classmethod
    def sandbox_enabled(cls) -> bool:
        """Allow sandbox only in non-production environments."""
        if cls.ENVIRONMENT == "production":
            return False
        return cls.ENABLE_SANDBOX

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

