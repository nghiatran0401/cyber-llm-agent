"""Integration tests for agent flow."""
import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import os

# Skip integration tests if no API key (they require real API calls)
pytestmark = pytest.mark.skipif(
    not os.getenv("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY not set - skipping integration tests"
)


def test_base_agent_initialization():
    """Test that base agent can be initialized."""
    from src.agents.g1.base_agent import CyberSecurityAgent
    
    agent = CyberSecurityAgent()
    assert agent is not None
    assert agent.llm is not None


def test_base_agent_analyze_log():
    """Test base agent can analyze a log entry."""
    from src.agents.g1.base_agent import CyberSecurityAgent
    
    agent = CyberSecurityAgent()
    test_log = "Failed login attempt from IP 192.168.1.100 after 5 tries"
    
    result = agent.analyze_log(test_log)
    assert result is not None
    assert len(result) > 0
    # Should contain some analysis
    assert not result.startswith("Error:")


def test_base_agent_empty_log():
    """Test base agent handles empty log gracefully."""
    from src.agents.g1.base_agent import CyberSecurityAgent
    
    agent = CyberSecurityAgent()
    result = agent.analyze_log("")
    assert "Error" in result or "empty" in result.lower()


@patch('src.agents.g1.simple_agent.ChatOpenAI')
def test_simple_agent_creation(mock_chat_openai):
    """Test simple agent can be created (mocked)."""
    from src.agents.g1.simple_agent import create_simple_agent
    
    # Mock the LLM
    mock_llm_instance = MagicMock()
    mock_chat_openai.return_value = mock_llm_instance
    
    # Mock the agent creation process
    with patch('src.agents.g1.simple_agent.create_agent') as mock_create_agent:
        with patch('src.agents.g1.simple_agent.Settings.validate') as mock_validate:
            mock_agent = MagicMock()
            mock_create_agent.return_value = mock_agent
            mock_validate.return_value = True
            
            agent = create_simple_agent(verbose=False)
            assert agent is not None


def test_simple_agent_with_real_api():
    """Test simple agent with real API (requires OPENAI_API_KEY)."""
    from src.agents.g1.simple_agent import create_simple_agent
    
    if not os.getenv("OPENAI_API_KEY"):
        pytest.skip("OPENAI_API_KEY not set")
    
    agent = create_simple_agent(verbose=False)
    assert agent is not None
    
    # Test with a simple query
    result = agent.invoke({
        "input": "What is a brute force attack?"
    })
    
    assert result is not None
    assert "output" in result
    assert len(result["output"]) > 0


def test_agent_tool_integration():
    """Test that agent can use tools."""
    from src.agents.g1.simple_agent import create_simple_agent
    from pathlib import Path
    
    if not os.getenv("OPENAI_API_KEY"):
        pytest.skip("OPENAI_API_KEY not set")
    
    # Ensure sample logs exist
    sample_log_path = Path("data/logs/sample_logs.txt")
    if not sample_log_path.exists():
        pytest.skip("Sample logs file not found")
    
    agent = create_simple_agent(verbose=False)
    
    # Test agent can parse logs
    result = agent.invoke({
        "input": f"Parse the logs from {sample_log_path.name} and tell me what threats you found."
    })
    
    assert result is not None
    assert "output" in result
    # Should have some analysis
    output = result["output"].lower()
    assert len(output) > 0


def test_agent_cti_fetch():
    """Test agent can fetch CTI intelligence."""
    from src.agents.g1.simple_agent import create_simple_agent
    
    if not os.getenv("OPENAI_API_KEY"):
        pytest.skip("OPENAI_API_KEY not set")
    
    agent = create_simple_agent(verbose=False)
    
    result = agent.invoke({
        "input": "Fetch CTI intelligence on ransomware threats."
    })
    
    assert result is not None
    assert "output" in result
    output = result["output"].lower()
    assert len(output) > 0

