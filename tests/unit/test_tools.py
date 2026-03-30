"""Unit tests for security tools."""
from unittest.mock import mock_open, patch
from pathlib import Path

from src.tools.log_parser_tool import parse_system_log
from src.tools.cti_tool import fetch_cti_intelligence


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


class _OTXThreatOk:
    def search_pulses(self, query, max_results=25):
        return {
            "results": [
                {"name": "RansomPulse", "tags": ["ransomware", "windows"], "indicators": [1, 2]},
                {"name": "LockerCampaign", "tags": ["extortion"], "indicators": [1]},
            ]
        }

    def get_indicator_details_by_section(self, *args, **kwargs):
        raise AssertionError("not used for threat search")


class _OTXIocOk:
    def search_pulses(self, query, max_results=25):
        raise AssertionError("not used for IOC")

    def get_indicator_details_by_section(self, indicator_type, indicator, section="general"):
        return {
            "type": "IPv4",
            "reputation": 5,
            "pulse_info": {"pulses": [{"name": "PulseOne"}, {"name": "PulseTwo"}]},
        }


class _OTXRaises:
    def __init__(self, exc):
        self._exc = exc

    def search_pulses(self, query, max_results=25):
        raise self._exc

    def get_indicator_details_by_section(self, *args, **kwargs):
        raise self._exc


def test_cti_fetch_otx_threat_type_success(monkeypatch):
    """OTX provider resolves threat-type search and formats output."""
    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_API_KEY", "test-key")
    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_BASE_URL", "https://otx.test/api/v1")
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_TOP_RESULTS", 3)
    monkeypatch.setattr("src.tools.cti_tool._get_otx", lambda: _OTXThreatOk())
    result = fetch_cti_intelligence("ransomware")
    assert "Source: AlienVault OTX" in result
    assert "Found 2 pulse result(s)" in result
    assert "RansomPulse" in result


def test_cti_fetch_otx_ioc_success(monkeypatch):
    """OTX provider resolves IOC lookups and reports pulse linkage."""
    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_API_KEY", "test-key")
    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_BASE_URL", "https://otx.test/api/v1")
    monkeypatch.setattr("src.tools.cti_tool._get_otx", lambda: _OTXIocOk())
    result = fetch_cti_intelligence("ioc:ip:1.2.3.4")
    assert "Query: ioc:ip:1.2.3.4" in result
    assert "Associated pulses: 2" in result
    assert "PulseOne" in result


def test_cti_fetch_otx_timeout_fallback(monkeypatch):
    """Timeouts degrade safely to fallback response."""
    import requests

    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_API_KEY", "test-key")
    monkeypatch.setattr("src.tools.cti_tool._get_otx", lambda: _OTXRaises(requests.Timeout()))
    result = fetch_cti_intelligence("phishing")
    assert "Source: CTI Fallback" in result
    assert "temporarily unavailable" in result.lower()


def test_cti_fetch_otx_http_429_fallback(monkeypatch):
    """Upstream errors use deterministic fallback text."""
    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_API_KEY", "test-key")
    monkeypatch.setattr("src.tools.cti_tool._get_otx", lambda: _OTXRaises(RuntimeError("429")))
    result = fetch_cti_intelligence("ddos")
    assert "Source: CTI Fallback" in result


def test_cti_fetch_invalid_ioc_input(monkeypatch):
    """Malformed IOC input yields a deterministic error."""
    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_API_KEY", "test-key")
    result = fetch_cti_intelligence("ioc:ip:")
    assert "error:" in result.lower()


def test_cti_fetch_output_sanitized_and_truncated(monkeypatch):
    """External text is sanitized and bounded by CTI_MAX_RESPONSE_CHARS."""

    class _OTXTruncate:
        def search_pulses(self, query, max_results=25):
            return {
                "results": [
                    {"name": "Bad\x00PulseName", "tags": ["x"], "indicators": [1]},
                    {"name": "AnotherVeryLongPulseNameThatShouldContributeToTruncation", "tags": ["y"], "indicators": [1]},
                ]
            }

        def get_indicator_details_by_section(self, *args, **kwargs):
            raise AssertionError("not used")

    monkeypatch.setattr("src.tools.cti_tool.Settings.OTX_API_KEY", "test-key")
    monkeypatch.setattr("src.tools.cti_tool.Settings.CTI_MAX_RESPONSE_CHARS", 160)
    monkeypatch.setattr("src.tools.cti_tool._get_otx", lambda: _OTXTruncate())
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
