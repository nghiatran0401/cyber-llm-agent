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

    # Paths
    BASE_DIR = Path(__file__).parent.parent.parent
    DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
    LOGS_DIR = Path(os.getenv("LOGS_DIR", DATA_DIR / "logs"))
    SESSIONS_DIR = Path(os.getenv("SESSIONS_DIR", DATA_DIR / "sessions"))
    BENCHMARKS_DIR = DATA_DIR / "benchmarks"
    CTI_FEEDS_DIR = DATA_DIR / "cti_feeds"
    
    # Ensure directories exist
    @classmethod
    def ensure_directories(cls):
        """Create necessary directories if they don't exist."""
        cls.DATA_DIR.mkdir(exist_ok=True)
        cls.LOGS_DIR.mkdir(exist_ok=True)
        cls.SESSIONS_DIR.mkdir(exist_ok=True)
        cls.BENCHMARKS_DIR.mkdir(exist_ok=True)
        cls.CTI_FEEDS_DIR.mkdir(exist_ok=True)
    
    @classmethod
    def validate(cls):
        """Validate that required settings are present."""
        allowed_envs = {"development", "staging", "production"}
        if cls.ENVIRONMENT not in allowed_envs:
            raise ValueError(
                f"ENVIRONMENT must be one of {sorted(allowed_envs)}; got '{cls.ENVIRONMENT}'."
            )
        if not cls.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY is required. Set it in .env file.")
        if not (0.0 <= cls.TEMPERATURE <= 1.0):
            raise ValueError("TEMPERATURE must be between 0.0 and 1.0.")
        if cls.MAX_TOKENS <= 0:
            raise ValueError("MAX_TOKENS must be greater than 0.")
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

