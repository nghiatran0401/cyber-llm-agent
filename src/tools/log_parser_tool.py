"""Log Parser Tool: reads log files and extracts security-relevant entries via Grok."""

import json
import re
from pathlib import Path

from langchain_core.tools import Tool
from pygrok import Grok

from src.config.settings import Settings
from src.utils.logger import setup_logger

logger = setup_logger(__name__)

_GROK_PATTERNS = [
    Grok("%{COMBINEDAPACHELOG}"),
    Grok("%{SYSLOGBASE} %{GREEDYDATA:syslog_message}"),
    Grok(r"%{TIMESTAMP_ISO8601:timestamp} \[%{LOGLEVEL:level}\] %{GREEDYDATA:message}"),
]

_SECURITY_KEYWORDS = [
    'failed', 'error', 'unauthorized', 'denied', 'attack',
    'suspicious', 'breach', 'malware', 'intrusion', 'scan',
    'xss', 'sql injection', 'sqli', 'brute force', 'credential stuffing',
]


def _resolve_safe_log_path(log_file_path: str) -> Path:
    """Resolve log path and prevent traversal outside approved directories."""
    raw_path = Path(log_file_path)
    candidate = raw_path if raw_path.is_absolute() else (Settings.LOGS_DIR / raw_path)
    resolved = candidate.resolve()
    allowed_root = Settings.LOGS_DIR.resolve()

    if allowed_root not in resolved.parents and resolved != allowed_root:
        raise ValueError("Invalid log file path. Access outside data/logs is not allowed.")

    if resolved.suffix.lower() not in Settings.ALLOWED_LOG_EXTENSIONS:
        raise ValueError(
            "Unsupported log file extension. "
            f"Allowed: {', '.join(sorted(Settings.ALLOWED_LOG_EXTENSIONS))}."
        )

    return resolved


def parse_system_log(log_file_path: str) -> str:
    """Parse system logs and extract security-relevant entries using Grok.

    Args:
        log_file_path: Path to the log file (relative to data/logs or absolute).

    Returns:
        JSON string of structured, security-relevant log entries.
    """
    try:
        log_path = _resolve_safe_log_path(log_file_path)

        if not log_path.exists():
            logger.warning("Log file not found: %s", log_path)
            return "No log file found at the specified path."

        relevant_logs = []

        with open(log_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                clean_line = line.strip()
                if not clean_line:
                    continue

                # Filter non-security lines first (fast, avoids expensive Grok matching)
                if not any(kw in clean_line.lower() for kw in _SECURITY_KEYWORDS):
                    continue

                # Try structured Grok parsing
                parsed_match = None
                for grok in _GROK_PATTERNS:
                    match = grok.match(clean_line)
                    if match:
                        parsed_match = match
                        break

                if parsed_match:
                    parsed_match['_raw'] = clean_line
                    parsed_match['_line'] = line_num
                    relevant_logs.append(parsed_match)
                else:
                    relevant_logs.append({
                        "_raw": clean_line,
                        "_line": line_num,
                        "note": "Unstructured alert",
                    })

        if not relevant_logs:
            logger.info("No security-relevant entries found in %s", log_path)
            return "No security-relevant entries found in the log file."

        logger.info("Parsed %d security-relevant entries from %s", len(relevant_logs), log_path)
        return json.dumps(relevant_logs, indent=2)

    except ValueError as e:
        logger.warning(str(e))
        return f"Error: {e}"
    except FileNotFoundError:
        logger.error("Log file not found: %s", log_file_path)
        return f"Log file not found: {log_file_path}"
    except PermissionError:
        logger.error("Permission denied reading log file: %s", log_file_path)
        return f"Permission denied reading log file: {log_file_path}"
    except Exception as e:
        logger.error("Error parsing log file: %s", e, exc_info=True)
        return f"Error parsing log file: {e}"


log_parser = Tool(
    name="LogParser",
    func=parse_system_log,
    description=(
        "Parses system log files and extracts security-relevant entries using Grok patterns. "
        "Input should be a file path under data/logs/ (relative or absolute). "
        "Returns structured JSON with fields like timestamp, level, message, and raw line."
    ),
)
