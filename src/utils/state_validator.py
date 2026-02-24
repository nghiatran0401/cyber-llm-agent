"""State validation and transition logging for multiagent workflow."""

from typing import Dict, Iterable, Any

from src.utils.logger import setup_logger

logger = setup_logger(__name__)


REQUIRED_STATE_KEYS = (
    "logs",
    "log_analysis",
    "threat_prediction",
    "incident_response",
    "final_report",
)


def validate_state(state: Dict[str, Any], required_keys: Iterable[str] = REQUIRED_STATE_KEYS) -> bool:
    """Validate required state keys are present."""
    missing = [key for key in required_keys if key not in state]
    if missing:
        raise ValueError(f"Missing required state keys: {missing}")
    return True


def log_state(state: Dict[str, Any], node_name: str):
    """Emit state transition debug metadata."""
    preview = {
        "logs_len": len(str(state.get("logs", ""))),
        "analysis_len": len(str(state.get("log_analysis", ""))),
        "prediction_len": len(str(state.get("threat_prediction", ""))),
        "response_len": len(str(state.get("incident_response", ""))),
        "final_len": len(str(state.get("final_report", ""))),
    }
    logger.info("[%s] state transition: %s", node_name, preview)

