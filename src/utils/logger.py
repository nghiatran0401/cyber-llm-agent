"""Structured logging for agent operations."""
import logging
import json
from datetime import datetime
from pathlib import Path
from src.config.settings import Settings


def setup_logger(name: str, level: str = None) -> logging.Logger:
    """Setup structured logger.
    
    Args:
        name: Logger name (typically __name__)
        level: Logging level (defaults to Settings.LOG_LEVEL)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Use provided level or default from settings
    log_level = level or Settings.LOG_LEVEL
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Avoid adding handlers multiple times
    if logger.handlers:
        return logger
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, log_level.upper()))
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (optional, for production)
    if Settings.ENVIRONMENT == "production":
        log_file = Settings.DATA_DIR / "logs" / f"{name}.log"
        log_file.parent.mkdir(exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def log_structured(logger: logging.Logger, level: str, message: str, **kwargs):
    """Log structured data as JSON.
    
    Args:
        logger: Logger instance
        level: Log level (info, warning, error, etc.)
        message: Log message
        **kwargs: Additional structured data
    """
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "message": message,
        **kwargs
    }
    
    log_method = getattr(logger, level.lower(), logger.info)
    log_method(json.dumps(log_data, indent=2))

