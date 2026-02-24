"""Unit tests for security tools."""
import pytest
from unittest.mock import mock_open, patch, MagicMock
from pathlib import Path
from src.tools.security_tools import parse_system_log, fetch_cti_intelligence
from src.config.settings import Settings


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


def test_cti_fetch_ransomware():
    """Test CTI fetch functionality for ransomware."""
    result = fetch_cti_intelligence("ransomware")
    assert len(result) > 0
    assert "ransomware" in result.lower() or "threat" in result.lower() or "intelligence" in result.lower()


def test_cti_fetch_ddos():
    """Test CTI fetch for DDoS threat type."""
    result = fetch_cti_intelligence("ddos")
    assert len(result) > 0
    assert "ddos" in result.lower() or "threat" in result.lower() or "intelligence" in result.lower()


def test_cti_fetch_unknown_threat():
    """Test CTI fetch for unknown threat type."""
    result = fetch_cti_intelligence("unknown_threat_xyz")
    assert len(result) > 0
    assert "threat intelligence" in result.lower() or "recommendation" in result.lower()


def test_cti_fetch_empty_input():
    """Test CTI fetch handles empty input."""
    result = fetch_cti_intelligence("")
    assert "error" in result.lower() or "empty" in result.lower()


def test_cti_fetch_phishing():
    """Test CTI fetch for phishing threat type."""
    result = fetch_cti_intelligence("phishing")
    assert len(result) > 0
    assert "phishing" in result.lower() or "threat" in result.lower()


def test_cti_fetch_brute_force():
    """Test CTI fetch for brute force threat type."""
    result = fetch_cti_intelligence("brute force")
    assert len(result) > 0
    assert "brute" in result.lower() or "threat" in result.lower()


def test_log_parser_with_absolute_path():
    """Test log parser with absolute path."""
    mock_data = "2026-01-27 Failed login attempt"
    abs_path = "/absolute/path/to/logs.txt"
    
    with patch("builtins.open", mock_open(read_data=mock_data)):
        with patch.object(Path, 'exists', return_value=True):
            with patch.object(Path, 'is_absolute', return_value=True):
                result = parse_system_log(abs_path)
                assert len(result) > 0

