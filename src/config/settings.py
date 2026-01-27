"""Centralized configuration management."""
import os
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables
load_dotenv()


class Settings:
    """Application settings loaded from environment variables."""
    
    # API Keys
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    HUGGINGFACE_API_KEY = os.getenv("HUGGINGFACE_API_KEY", "")
    
    # Model Configuration
    MODEL_NAME = os.getenv("MODEL_NAME", "gpt-3.5-turbo")
    TEMPERATURE = float(os.getenv("TEMPERATURE", "0.5"))
    MAX_TOKENS = int(os.getenv("MAX_TOKENS", "2000"))
    
    # Environment
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    
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
        if not cls.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY is required. Set it in .env file.")
        return True


# Initialize directories on import
Settings.ensure_directories()

