"""Structured logging for agent operations."""
import json
import logging
from datetime import datetime

_DEFAULT_LOG_LEVEL = "INFO"


def setup_logger(name: str, level: str | None = None) -> logging.Logger:
    """Setup structured logger.

    Args:
        name: Logger name (typically __name__)
        level: Logging level name (defaults to INFO)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    log_level = level or _DEFAULT_LOG_LEVEL
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

