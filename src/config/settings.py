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
    HUGGINGFACE_API_KEY = os.getenv("HUGGINGFACE_API_KEY", "")

    # Model Configuration
    MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4o-mini")
    FAST_MODEL_NAME = os.getenv("FAST_MODEL_NAME", MODEL_NAME)
    STRONG_MODEL_NAME = os.getenv("STRONG_MODEL_NAME", "gpt-4o")
    AUTO_MODEL_ROUTING = os.getenv("AUTO_MODEL_ROUTING", "true").lower() == "true"
    TOOL_MANDATORY_FOR_HIGH_RISK = os.getenv("TOOL_MANDATORY_FOR_HIGH_RISK", "true").lower() == "true"
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

    # CTI provider configuration
    CTI_PROVIDER = os.getenv("CTI_PROVIDER", "otx").lower()
    OTX_API_KEY = os.getenv("OTX_API_KEY", "")
    OTX_BASE_URL = os.getenv("OTX_BASE_URL", "https://otx.alienvault.com/api/v1").rstrip("/")
    CTI_REQUEST_TIMEOUT_SECONDS = int(os.getenv("CTI_REQUEST_TIMEOUT_SECONDS", "10"))
    CTI_MAX_RETRIES = int(os.getenv("CTI_MAX_RETRIES", "2"))
    CTI_RETRY_BACKOFF_SECONDS = float(os.getenv("CTI_RETRY_BACKOFF_SECONDS", "0.5"))
    CTI_MAX_RESPONSE_CHARS = int(os.getenv("CTI_MAX_RESPONSE_CHARS", "3000"))
    CTI_TOP_RESULTS = int(os.getenv("CTI_TOP_RESULTS", "5"))

    # RAG (basic local knowledge retrieval)
    ENABLE_RAG = os.getenv("ENABLE_RAG", "false").lower() == "true"
    RAG_CHUNK_SIZE = int(os.getenv("RAG_CHUNK_SIZE", "180"))
    RAG_MAX_RESULTS = int(os.getenv("RAG_MAX_RESULTS", "3"))
    RAG_RETRIEVAL_MODE = os.getenv("RAG_RETRIEVAL_MODE", "hybrid").lower()
    RAG_EMBEDDING_DIMS = int(os.getenv("RAG_EMBEDDING_DIMS", "96"))
    RAG_SEMANTIC_CANDIDATES = int(os.getenv("RAG_SEMANTIC_CANDIDATES", "8"))

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
        if cls.CTI_PROVIDER != "otx":
            raise ValueError("CTI_PROVIDER must be 'otx'. Mock CTI has been removed.")
        if not cls.OTX_API_KEY:
            raise ValueError("OTX_API_KEY is required when CTI_PROVIDER=otx.")
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
        if cls.RAG_CHUNK_SIZE <= 0:
            raise ValueError("RAG_CHUNK_SIZE must be greater than 0.")
        if cls.RAG_MAX_RESULTS <= 0:
            raise ValueError("RAG_MAX_RESULTS must be greater than 0.")
        if cls.RAG_RETRIEVAL_MODE not in {"lexical", "semantic", "hybrid"}:
            raise ValueError("RAG_RETRIEVAL_MODE must be one of {'lexical','semantic','hybrid'}.")
        if cls.RAG_EMBEDDING_DIMS <= 0:
            raise ValueError("RAG_EMBEDDING_DIMS must be greater than 0.")
        if cls.RAG_SEMANTIC_CANDIDATES <= 0:
            raise ValueError("RAG_SEMANTIC_CANDIDATES must be greater than 0.")
        return True

    @classmethod
    def sandbox_enabled(cls) -> bool:
        """Allow sandbox only in non-production environments."""
        if cls.ENVIRONMENT == "production":
            return False
        return cls.ENABLE_SANDBOX

    @classmethod
    def is_high_risk_task(cls, task_text: str) -> bool:
        """Return True when task likely needs evidence-first tool use."""
        if not task_text:
            return False

        high_risk_keywords = (
            "incident",
            "compromise",
            "breach",
            "forensics",
            "malware",
            "ransomware",
            "phishing",
            "containment",
            "remediation",
            "critical",
            "exploit",
            "zero-day",
            "ioc",
            "siem",
            "edr",
            "block this ip",
            "quarantine",
            "production",
        )
        task_lower = task_text.lower()
        return any(keyword in task_lower for keyword in high_risk_keywords)

    @classmethod
    def should_use_strong_model(cls, task_text: str) -> bool:
        """Choose strong model for high-risk or complex prompts."""
        if not cls.AUTO_MODEL_ROUTING:
            return False
        if cls.is_high_risk_task(task_text):
            return True

        task_lower = (task_text or "").lower()
        complexity_hints = (
            "step-by-step",
            "multi-step",
            "investigate",
            "root cause",
            "correlate",
            "compare",
            "summarize all",
            "across",
        )
        return any(hint in task_lower for hint in complexity_hints)


# Initialize directories on import
Settings.ensure_directories()

