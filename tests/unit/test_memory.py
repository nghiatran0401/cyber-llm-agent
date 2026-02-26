"""Unit tests for memory and session behavior."""

from pathlib import Path
import json
from datetime import datetime, timedelta, timezone

from src.agents.g1.agent_with_memory import StatefulSecurityAgent
from src.utils.memory_manager import ConversationMemory
from src.utils.session_manager import SessionManager


class _FakeMessage:
    def __init__(self, content: str):
        self.content = content


class _FakeBackendAgent:
    def __init__(self):
        self.calls = []

    def invoke(self, payload):
        self.calls.append(payload)
        return {"messages": [_FakeMessage("simulated-response")]}


def test_buffer_memory_enforces_max_messages():
    memory = ConversationMemory(memory_type="buffer", max_messages=4)
    for idx in range(6):
        memory.add_turn("user", f"msg-{idx}")
    assert len(memory.messages) == 4
    assert memory.messages[0]["content"] == "msg-2"


def test_summary_memory_rolls_over_into_summary():
    memory = ConversationMemory(memory_type="summary", max_messages=3, max_summary_chars=200)
    for idx in range(6):
        memory.add_turn("assistant", f"answer-{idx}")
    assert len(memory.messages) == 3
    assert memory.running_summary
    assert "answer-0" in memory.running_summary


def test_long_term_memory_recall_returns_relevant_items():
    memory = ConversationMemory(memory_type="buffer", max_messages=4, recall_top_k=2)
    memory.update_long_term_from_turn(
        user_text="Investigate failed login bursts from VPN gateway",
        assistant_text="Severity: high\nSource: AlienVault OTX\nRecommended Actions:\n- Reset credentials",
    )
    memory.update_long_term_from_turn(
        user_text="Review SQL injection probe in login endpoint",
        assistant_text="Severity: medium\n- Investigate /login payload patterns",
    )

    recalled = memory.retrieve_relevant_memories("failed login credentials")
    assert recalled
    assert any("failed login" in item.lower() or "source:" in item.lower() for item in recalled)


def test_session_manager_save_and_load(tmp_path: Path):
    manager = SessionManager(session_dir=tmp_path)
    manager.save_session("abc_123", {"messages": [{"role": "user", "content": "hello"}]})
    restored = manager.load_session("abc_123")
    assert restored["session_id"] == "abc_123"
    assert restored["messages"][0]["content"] == "hello"


def test_stateful_agent_persists_memory_to_disk(tmp_path: Path):
    fake_backend = _FakeBackendAgent()
    agent = StatefulSecurityAgent(
        memory_type="buffer",
        max_messages=4,
        session_id="memory_test",
        backend_agent=fake_backend,
        verbose=False,
    )
    agent.session_manager = SessionManager(session_dir=tmp_path)

    result = agent.invoke({"input": "Analyze login failures"})

    assert "messages" in result
    assert len(fake_backend.calls) == 1
    saved = agent.session_manager.load_session("memory_test")
    assert saved["messages"]
    assert saved["messages"][-1]["content"] == "simulated-response"
    assert "episodic_memories" in saved
    assert "semantic_facts" in saved
    assert saved["episodic_memories"]


def test_session_manager_prunes_expired_sessions(tmp_path: Path, monkeypatch):
    manager = SessionManager(session_dir=tmp_path)
    monkeypatch.setattr("src.utils.session_manager.Settings.SESSION_RETENTION_DAYS", 1)
    old_payload = {
        "session_id": "old_session",
        "updated_at": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat(),
        "messages": [],
    }
    old_file = tmp_path / "old_session.json"
    old_file.write_text(json.dumps(old_payload), encoding="utf-8")

    manager.prune_expired_sessions()
    assert not old_file.exists()

