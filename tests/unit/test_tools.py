"""Unit tests for security tools."""
import json
from unittest.mock import mock_open, patch, MagicMock
from pathlib import Path

import requests

from src.tools.log_parser_tool import parse_system_log
from src.tools.cti_tool import fetch_cti_intelligence


def _parse_envelope(result: str) -> dict:
    """Parse a ToolResult envelope from JSON string."""
    parsed = json.loads(result)
    assert "ok" in parsed
    assert "data" in parsed
    assert "error" in parsed
    assert "meta" in parsed
    assert "tool" in parsed["meta"]
    return parsed


# ── Log Parser Tests (happy path) ──────────────────────────────────────────────

def test_log_parser_with_mock_file():
    """Test log parser with known input returns ToolResult envelope."""
    mock_data = """2026-01-27 Failed login from 192.168.1.1
2026-01-27 Success login from 192.168.1.2
2026-01-27 Error: Connection timeout
2026-01-27 Normal operation"""

    with patch("builtins.open", mock_open(read_data=mock_data)):
        with patch.object(Path, 'exists', return_value=True):
            with patch.object(Path, 'is_absolute', return_value=False):
                result = parse_system_log("fake_path.txt")
                envelope = _parse_envelope(result)
                assert envelope["ok"] is True
                assert envelope["meta"]["tool"] == "LogParser"
                assert isinstance(envelope["data"], list)
                assert len(envelope["data"]) > 0
                assert envelope["meta"]["entries_count"] > 0


def test_log_parser_file_not_found():
    """Test log parser handles missing file with error envelope."""
    with patch.object(Path, 'exists', return_value=False):
        result = parse_system_log("nonexistent.txt")
        envelope = _parse_envelope(result)
        assert envelope["ok"] is False
        assert envelope["error_type"] == "file_not_found"


def test_log_parser_no_security_entries():
    """Test log parser with no security-relevant entries."""
    mock_data = """2026-01-27 Normal operation
2026-01-27 System started
2026-01-27 User logged in successfully"""

    with patch("builtins.open", mock_open(read_data=mock_data)):
        with patch.object(Path, 'exists', return_value=True):
            with patch.object(Path, 'is_absolute', return_value=False):
                result = parse_system_log("normal_logs.txt")
                envelope = _parse_envelope(result)
                assert envelope["ok"] is True
                assert envelope["data"] == []
                assert envelope["meta"]["entries_count"] == 0


def test_log_parser_rejects_absolute_path_outside_logs_dir():
    """Absolute paths outside the logs directory are blocked."""
    abs_path = "/absolute/path/to/logs.txt"
    with patch.object(Path, 'exists', return_value=True):
        with patch.object(Path, 'is_absolute', return_value=True):
            result = parse_system_log(abs_path)
            envelope = _parse_envelope(result)
            assert envelope["ok"] is False
            assert envelope["error_type"] in ("path_traversal", "validation_error")


# ── Log Parser Tests (unhappy path) ───────────────────────────────────────────

def test_log_parser_permission_error():
    """Permission denied returns structured error."""
    with patch.object(Path, 'exists', return_value=True):
        with patch.object(Path, 'is_absolute', return_value=False):
            with patch("builtins.open", side_effect=PermissionError("denied")):
                result = parse_system_log("restricted.log")
                envelope = _parse_envelope(result)
                assert envelope["ok"] is False
                assert envelope["error_type"] == "permission_denied"
                assert "permission denied" in envelope["error"].lower()


def test_log_parser_encoding_error():
    """Encoding error returns structured error."""
    with patch.object(Path, 'exists', return_value=True):
        with patch.object(Path, 'is_absolute', return_value=False):
            with patch("builtins.open", side_effect=UnicodeDecodeError("utf-8", b"", 0, 1, "invalid")):
                result = parse_system_log("binary.log")
                envelope = _parse_envelope(result)
                assert envelope["ok"] is False
                assert envelope["error_type"] == "encoding_error"


def test_log_parser_empty_file():
    """Empty file returns ok with zero entries."""
    with patch("builtins.open", mock_open(read_data="")):
        with patch.object(Path, 'exists', return_value=True):
            with patch.object(Path, 'is_absolute', return_value=False):
                result = parse_system_log("empty.log")
                envelope = _parse_envelope(result)
                assert envelope["ok"] is True
                assert envelope["data"] == []
                assert envelope["meta"]["entries_count"] == 0


def test_log_parser_large_file_line_count():
    """Large file with few security entries returns only security entries."""
    lines = ["2026-01-27 Normal operation\n"] * 10000
    lines[42] = "2026-01-27 Failed login from 192.168.1.1\n"
    lines[100] = "2026-01-27 Unauthorized access attempt\n"
    lines[5000] = "2026-01-27 SQL injection detected\n"
    lines[9999] = "2026-01-27 Brute force attack from 10.0.0.1\n"
    mock_data = "".join(lines)

    with patch("builtins.open", mock_open(read_data=mock_data)):
        with patch.object(Path, 'exists', return_value=True):
            with patch.object(Path, 'is_absolute', return_value=False):
                result = parse_system_log("big.log")
                envelope = _parse_envelope(result)
                assert envelope["ok"] is True
                assert envelope["meta"]["entries_count"] == 4


def test_log_parser_unsupported_extension():
    """Unsupported file extension returns validation error."""
    result = parse_system_log("data.csv")
    envelope = _parse_envelope(result)
    assert envelope["ok"] is False
    assert "unsupported" in envelope["error"].lower() or "extension" in envelope["error"].lower()


# ── CTI Tool Tests (happy path) ────────────────────────────────────────────────

class _FakeResponse:
    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def test_cti_fetch_otx_threat_type_success(monkeypatch):
    """OTX provider resolves threat-type search and returns envelope."""
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_PROVIDER", "otx")
    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_API_KEY", "test-key")
    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_BASE_URL", "https://otx.test/api/v1")
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_MAX_RETRIES", 0)
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_REQUEST_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_TOP_RESULTS", 3)
    with patch("src.tools.cti_tool.requests.get", return_value=_FakeResponse(200, {
        "results": [
            {"name": "RansomPulse", "tags": ["ransomware", "windows"], "indicators": [1, 2]},
            {"name": "LockerCampaign", "tags": ["extortion"], "indicators": [1]},
        ]
    })):
        result = fetch_cti_intelligence("ransomware")
    envelope = _parse_envelope(result)
    assert envelope["ok"] is True
    assert envelope["meta"]["tool"] == "CTIFetch"
    assert "Source: AlienVault OTX" in envelope["data"]
    assert "Found 2 pulse result(s)" in envelope["data"]
    assert "RansomPulse" in envelope["data"]


def test_cti_fetch_otx_ioc_success(monkeypatch):
    """OTX provider resolves IOC lookups and reports pulse linkage."""
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_PROVIDER", "otx")
    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_API_KEY", "test-key")
    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_BASE_URL", "https://otx.test/api/v1")
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_MAX_RETRIES", 0)
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_REQUEST_TIMEOUT_SECONDS", 1)
    with patch("src.tools.cti_tool.requests.get", return_value=_FakeResponse(200, {
        "type": "IPv4",
        "reputation": 5,
        "pulse_info": {"pulses": [{"name": "PulseOne"}, {"name": "PulseTwo"}]},
    })):
        result = fetch_cti_intelligence("ioc:ip:1.2.3.4")
    envelope = _parse_envelope(result)
    assert envelope["ok"] is True
    assert "Query: ioc:ip:1.2.3.4" in envelope["data"]
    assert "Associated pulses: 2" in envelope["data"]


def test_cti_fetch_otx_timeout_fallback(monkeypatch):
    """Timeouts degrade safely to fallback response."""
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_PROVIDER", "otx")
    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_API_KEY", "test-key")
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_MAX_RETRIES", 0)
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_REQUEST_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_RETRY_BACKOFF_SECONDS", 0)
    with patch("src.tools.cti_tool.requests.get", side_effect=requests.Timeout()):
        result = fetch_cti_intelligence("phishing")
    envelope = _parse_envelope(result)
    assert envelope["ok"] is True  # fallback is valid content
    assert "Source: CTI Fallback" in envelope["data"]
    assert "temporarily unavailable" in envelope["data"].lower()


def test_cti_fetch_otx_http_429_fallback(monkeypatch):
    """Rate-limit responses use deterministic fallback text."""
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_PROVIDER", "otx")
    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_API_KEY", "test-key")
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_MAX_RETRIES", 0)
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_REQUEST_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_RETRY_BACKOFF_SECONDS", 0)
    with patch("src.tools.cti_tool.requests.get", return_value=_FakeResponse(429, {})):
        result = fetch_cti_intelligence("ddos")
    envelope = _parse_envelope(result)
    assert envelope["ok"] is True
    assert "Source: CTI Fallback" in envelope["data"]


def test_cti_fetch_invalid_ioc_input(monkeypatch):
    """Malformed IOC input yields a deterministic error envelope."""
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_PROVIDER", "otx")
    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_API_KEY", "test-key")
    result = fetch_cti_intelligence("ioc:ip:")
    envelope = _parse_envelope(result)
    assert envelope["ok"] is False
    assert envelope["error_type"] == "invalid_ioc_format"


def test_cti_fetch_output_sanitized_and_truncated(monkeypatch):
    """External text is sanitized and bounded by CTI_MAX_RESPONSE_CHARS."""
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_PROVIDER", "otx")
    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_API_KEY", "test-key")
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_MAX_RETRIES", 0)
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_MAX_RESPONSE_CHARS", 160)
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_RETRY_BACKOFF_SECONDS", 0)
    with patch("src.tools.cti_tool.requests.get", return_value=_FakeResponse(200, {
        "results": [
            {"name": "Bad\x00PulseName", "tags": ["x"], "indicators": [1]},
            {"name": "AnotherVeryLongPulseNameThatShouldContributeToTruncation", "tags": ["y"], "indicators": [1]},
        ]
    })):
        result = fetch_cti_intelligence("malware")
    envelope = _parse_envelope(result)
    assert envelope["ok"] is True
    assert "\x00" not in envelope["data"]
    assert len(envelope["data"]) <= 160


# ── CTI Tool Tests (unhappy path) ─────────────────────────────────────────────

def test_cti_fetch_http_500_retries_then_fallback(monkeypatch):
    """HTTP 500 triggers retries then fallback."""
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_PROVIDER", "otx")
    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_API_KEY", "test-key")
    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_BASE_URL", "https://otx.test/api/v1")
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_MAX_RETRIES", 2)
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_REQUEST_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_RETRY_BACKOFF_SECONDS", 0)
    mock_get = MagicMock(return_value=_FakeResponse(500, {}))
    with patch("src.tools.cti_tool.requests.get", mock_get):
        result = fetch_cti_intelligence("ransomware")
    envelope = _parse_envelope(result)
    assert envelope["ok"] is True  # fallback
    assert "CTI Fallback" in envelope["data"]
    assert mock_get.call_count == 3  # 1 initial + 2 retries


def test_cti_fetch_json_parse_error(monkeypatch):
    """Malformed JSON response triggers fallback."""
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_PROVIDER", "otx")
    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_API_KEY", "test-key")
    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_BASE_URL", "https://otx.test/api/v1")
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_MAX_RETRIES", 0)
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_REQUEST_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_RETRY_BACKOFF_SECONDS", 0)
    bad_response = MagicMock()
    bad_response.status_code = 200
    bad_response.json.side_effect = ValueError("bad json")
    with patch("src.tools.cti_tool.requests.get", return_value=bad_response):
        result = fetch_cti_intelligence("malware")
    envelope = _parse_envelope(result)
    assert envelope["ok"] is True
    assert "CTI Fallback" in envelope["data"]


def test_cti_fetch_empty_query():
    """Empty query returns error envelope."""
    result = fetch_cti_intelligence("")
    envelope = _parse_envelope(result)
    assert envelope["ok"] is False
    assert envelope["error_type"] == "empty_query"


def test_cti_fetch_missing_api_key(monkeypatch):
    """Missing API key still uses fallback gracefully."""
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_PROVIDER", "otx")
    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_API_KEY", "")
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_MAX_RETRIES", 0)
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_REQUEST_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_RETRY_BACKOFF_SECONDS", 0)
    with patch("src.tools.cti_tool.requests.get", side_effect=requests.ConnectionError("refused")):
        result = fetch_cti_intelligence("phishing")
    envelope = _parse_envelope(result)
    assert envelope["ok"] is True
    assert "CTI Fallback" in envelope["data"]
