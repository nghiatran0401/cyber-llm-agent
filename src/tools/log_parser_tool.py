"""Log Parser Tool: reads log files and extracts security-relevant entries via Grok."""

import json
import re
from pathlib import Path
from time import perf_counter

from langchain_core.tools import Tool
from pygrok import Grok

from src.config.settings import Settings
from src.utils.logger import setup_logger

from ._tool_envelope import build_tool_result, serialize_tool_result

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
        JSON string containing a ToolResult envelope with structured log entries.
    """
    start = perf_counter()
    try:
        log_path = _resolve_safe_log_path(log_file_path)

        if not log_path.exists():
            logger.warning("Log file not found: %s", log_path)
            duration_ms = int((perf_counter() - start) * 1000)
            return serialize_tool_result(build_tool_result(
                ok=False, tool="LogParser", error="No log file found at the specified path.",
                error_type="file_not_found", duration_ms=duration_ms, input_val=log_file_path,
            ))

        relevant_logs = []

        with open(log_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                clean_line = line.strip()
                if not clean_line:
                    continue

                if not any(kw in clean_line.lower() for kw in _SECURITY_KEYWORDS):
                    continue

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

        duration_ms = int((perf_counter() - start) * 1000)

        if not relevant_logs:
            logger.info("No security-relevant entries found in %s", log_path)
            return serialize_tool_result(build_tool_result(
                ok=True, tool="LogParser", data=[],
                duration_ms=duration_ms, entries_count=0, input_val=log_file_path,
            ))

        logger.info("Parsed %d security-relevant entries from %s (duration=%dms)", len(relevant_logs), log_path, duration_ms)
        return serialize_tool_result(build_tool_result(
            ok=True, tool="LogParser", data=relevant_logs,
            duration_ms=duration_ms, entries_count=len(relevant_logs), input_val=log_file_path,
        ))

    except UnicodeDecodeError as e:
        duration_ms = int((perf_counter() - start) * 1000)
        logger.error("Encoding error reading log file: %s", log_file_path)
        return serialize_tool_result(build_tool_result(
            ok=False, tool="LogParser", error=f"Encoding error reading log file: {e}",
            error_type="encoding_error", duration_ms=duration_ms, input_val=log_file_path,
        ))
    except ValueError as e:
        duration_ms = int((perf_counter() - start) * 1000)
        error_type = "path_traversal" if "outside" in str(e).lower() else "validation_error"
        logger.warning("LogParser validation error: %s (duration=%dms)", e, duration_ms)
        return serialize_tool_result(build_tool_result(
            ok=False, tool="LogParser", error=str(e),
            error_type=error_type, duration_ms=duration_ms, input_val=log_file_path,
        ))
    except FileNotFoundError:
        duration_ms = int((perf_counter() - start) * 1000)
        logger.error("Log file not found: %s", log_file_path)
        return serialize_tool_result(build_tool_result(
            ok=False, tool="LogParser", error=f"Log file not found: {log_file_path}",
            error_type="file_not_found", duration_ms=duration_ms, input_val=log_file_path,
        ))
    except PermissionError:
        duration_ms = int((perf_counter() - start) * 1000)
        logger.error("Permission denied reading log file: %s", log_file_path)
        return serialize_tool_result(build_tool_result(
            ok=False, tool="LogParser", error=f"Permission denied reading log file: {log_file_path}",
            error_type="permission_denied", duration_ms=duration_ms, input_val=log_file_path,
        ))
    except Exception as e:
        duration_ms = int((perf_counter() - start) * 1000)
        logger.error("Error parsing log file: %s", e, exc_info=True)
        return serialize_tool_result(build_tool_result(
            ok=False, tool="LogParser", error=f"Error parsing log file: {e}",
            error_type="unknown", duration_ms=duration_ms, input_val=log_file_path,
        ))


log_parser = Tool(
    name="LogParser",
    func=parse_system_log,
    description=(
        "Parses system log files and extracts security-relevant entries using Grok patterns. "
        "Input should be a file path under data/logs/ (relative or absolute). "
        "Returns structured JSON with fields like timestamp, level, message, and raw line."
    ),
)
