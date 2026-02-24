"""Unit tests for security tools."""
from unittest.mock import mock_open, patch
from pathlib import Path

import requests

from src.tools.security_tools import parse_system_log, fetch_cti_intelligence


def test_log_parser_with_mock_file():
    """Test log parser with known input."""
    mock_data = """2026-01-27 Failed login from 192.168.1.1
2026-01-27 Success login from 192.168.1.2
2026-01-27 Error: Connection timeout
2026-01-27 Normal operation"""
    
    with patch("builtins.open", mock_open(read_data=mock_data)):
        with patch.object(Path, 'exists', return_value=True):
            with patch.object(Path, 'is_absolute', return_value=False):
                result = parse_system_log("fake_path.txt")
                assert len(result) > 0
                assert "Failed" in result or "Error" in result
                assert "Line 1" in result or "Line 3" in result


def test_log_parser_file_not_found():
    """Test log parser handles missing file gracefully."""
    with patch.object(Path, 'exists', return_value=False):
        result = parse_system_log("nonexistent.txt")
        assert "not found" in result.lower() or "No log file" in result


def test_log_parser_no_security_entries():
    """Test log parser with no security-relevant entries."""
    mock_data = """2026-01-27 Normal operation
2026-01-27 System started
2026-01-27 User logged in successfully"""
    
    with patch("builtins.open", mock_open(read_data=mock_data)):
        with patch.object(Path, 'exists', return_value=True):
            with patch.object(Path, 'is_absolute', return_value=False):
                result = parse_system_log("normal_logs.txt")
                assert "No security-relevant" in result or "not found" in result.lower()


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def test_cti_fetch_otx_threat_type_success(monkeypatch):
    """OTX provider resolves threat-type search and formats output."""
    monkeypatch.setattr("src.tools.security_tools.Settings.CTI_PROVIDER", "otx")
    monkeypatch.setattr("src.tools.security_tools.Settings.OTX_API_KEY", "test-key")
    monkeypatch.setattr("src.tools.security_tools.Settings.OTX_BASE_URL", "https://otx.test/api/v1")
    monkeypatch.setattr("src.tools.security_tools.Settings.CTI_MAX_RETRIES", 0)
    monkeypatch.setattr("src.tools.security_tools.Settings.CTI_REQUEST_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr("src.tools.security_tools.Settings.CTI_TOP_RESULTS", 3)
    with patch("src.tools.security_tools.requests.get", return_value=_FakeResponse(200, {
        "results": [
            {"name": "RansomPulse", "tags": ["ransomware", "windows"], "indicators": [1, 2]},
            {"name": "LockerCampaign", "tags": ["extortion"], "indicators": [1]},
        ]
    })):
        result = fetch_cti_intelligence("ransomware")
    assert "Source: AlienVault OTX" in result
    assert "Found 2 pulse result(s)" in result
    assert "RansomPulse" in result


def test_cti_fetch_otx_ioc_success(monkeypatch):
    """OTX provider resolves IOC lookups and reports pulse linkage."""
    monkeypatch.setattr("src.tools.security_tools.Settings.CTI_PROVIDER", "otx")
    monkeypatch.setattr("src.tools.security_tools.Settings.OTX_API_KEY", "test-key")
    monkeypatch.setattr("src.tools.security_tools.Settings.OTX_BASE_URL", "https://otx.test/api/v1")
    monkeypatch.setattr("src.tools.security_tools.Settings.CTI_MAX_RETRIES", 0)
    monkeypatch.setattr("src.tools.security_tools.Settings.CTI_REQUEST_TIMEOUT_SECONDS", 1)
    with patch("src.tools.security_tools.requests.get", return_value=_FakeResponse(200, {
        "type": "IPv4",
        "reputation": 5,
        "pulse_info": {"pulses": [{"name": "PulseOne"}, {"name": "PulseTwo"}]},
    })):
        result = fetch_cti_intelligence("ioc:ip:1.2.3.4")
    assert "Query: ioc:ip:1.2.3.4" in result
    assert "Associated pulses: 2" in result
    assert "PulseOne" in result


def test_cti_fetch_otx_timeout_fallback(monkeypatch):
    """Timeouts degrade safely to fallback response."""
    monkeypatch.setattr("src.tools.security_tools.Settings.CTI_PROVIDER", "otx")
    monkeypatch.setattr("src.tools.security_tools.Settings.OTX_API_KEY", "test-key")
    monkeypatch.setattr("src.tools.security_tools.Settings.CTI_MAX_RETRIES", 0)
    monkeypatch.setattr("src.tools.security_tools.Settings.CTI_REQUEST_TIMEOUT_SECONDS", 1)
    with patch("src.tools.security_tools.requests.get", side_effect=requests.Timeout()):
        result = fetch_cti_intelligence("phishing")
    assert "Source: CTI Fallback" in result
    assert "temporarily unavailable" in result.lower()


def test_cti_fetch_otx_http_429_fallback(monkeypatch):
    """Rate-limit responses use deterministic fallback text."""
    monkeypatch.setattr("src.tools.security_tools.Settings.CTI_PROVIDER", "otx")
    monkeypatch.setattr("src.tools.security_tools.Settings.OTX_API_KEY", "test-key")
    monkeypatch.setattr("src.tools.security_tools.Settings.CTI_MAX_RETRIES", 0)
    monkeypatch.setattr("src.tools.security_tools.Settings.CTI_REQUEST_TIMEOUT_SECONDS", 1)
    with patch("src.tools.security_tools.requests.get", return_value=_FakeResponse(429, {})):
        result = fetch_cti_intelligence("ddos")
    assert "Source: CTI Fallback" in result


def test_cti_fetch_invalid_ioc_input(monkeypatch):
    """Malformed IOC input yields a deterministic error."""
    monkeypatch.setattr("src.tools.security_tools.Settings.CTI_PROVIDER", "otx")
    monkeypatch.setattr("src.tools.security_tools.Settings.OTX_API_KEY", "test-key")
    result = fetch_cti_intelligence("ioc:ip:")
    assert "error:" in result.lower()


def test_cti_fetch_output_sanitized_and_truncated(monkeypatch):
    """External text is sanitized and bounded by CTI_MAX_RESPONSE_CHARS."""
    monkeypatch.setattr("src.tools.security_tools.Settings.CTI_PROVIDER", "otx")
    monkeypatch.setattr("src.tools.security_tools.Settings.OTX_API_KEY", "test-key")
    monkeypatch.setattr("src.tools.security_tools.Settings.CTI_MAX_RETRIES", 0)
    monkeypatch.setattr("src.tools.security_tools.Settings.CTI_MAX_RESPONSE_CHARS", 160)
    with patch("src.tools.security_tools.requests.get", return_value=_FakeResponse(200, {
        "results": [
            {"name": "Bad\x00PulseName", "tags": ["x"], "indicators": [1]},
            {"name": "AnotherVeryLongPulseNameThatShouldContributeToTruncation", "tags": ["y"], "indicators": [1]},
        ]
    })):
        result = fetch_cti_intelligence("malware")
    assert "\x00" not in result
    assert len(result) <= 160


def test_log_parser_rejects_absolute_path_outside_logs_dir():
    """Absolute paths outside the logs directory are blocked."""
    mock_data = "2026-01-27 Failed login attempt"
    abs_path = "/absolute/path/to/logs.txt"
    
    with patch("builtins.open", mock_open(read_data=mock_data)):
        with patch.object(Path, 'exists', return_value=True):
            with patch.object(Path, 'is_absolute', return_value=True):
                result = parse_system_log(abs_path)
                assert "Invalid log file path" in result

