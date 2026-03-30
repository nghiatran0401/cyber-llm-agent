import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.agents.g1.g1_agent import G1Agent
from src.utils.memory_manager import ConversationMemory
from src.utils.session_manager import SessionManager


# ------------------------------------------------------------------
# Shared fakes
# ------------------------------------------------------------------

class _FakeMessage:
    def __init__(self, content: str):
        self.content = content


class _FakeBackendAgent:
    def __init__(self):
        self.calls = []

    def invoke(self, payload):
        self.calls.append(payload)
        return {"messages": [_FakeMessage("simulated-response")]}


# ------------------------------------------------------------------
# Stage 1 — buffer and summary basics
# ------------------------------------------------------------------

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


# ------------------------------------------------------------------
# Stage 1 — session manager basics
# ------------------------------------------------------------------

def test_session_manager_rejects_invalid_session_id(tmp_path: Path):
    manager = SessionManager(session_dir=tmp_path)
    with pytest.raises(ValueError, match="invalid character"):
        manager.save_session("user@domain", {"messages": []})


def test_session_manager_save_and_load(tmp_path: Path):
    manager = SessionManager(session_dir=tmp_path)
    manager.save_session("abc_123", {"messages": [{"role": "user", "content": "hello"}]})
    restored = manager.load_session("abc_123")
    assert restored["session_id"] == "abc_123"
    assert restored["messages"][0]["content"] == "hello"


def test_stateful_agent_persists_memory_to_disk(tmp_path: Path):
    fake_backend = _FakeBackendAgent()
    agent = G1Agent(
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


# ------------------------------------------------------------------
# Stage 1 — contract validation and hardening
# ------------------------------------------------------------------

def test_load_state_rejects_invalid_role():
    memory = ConversationMemory(memory_type="buffer", max_messages=4)
    with pytest.raises(ValueError, match="invalid role"):
        memory.load_state(messages=[{"role": "bot", "content": "hi"}])


def test_add_turn_rejects_invalid_role():
    memory = ConversationMemory(memory_type="buffer", max_messages=4)
    with pytest.raises(ValueError, match="Invalid role"):
        memory.add_turn("bot", "hello")


def test_load_state_rejects_missing_keys():
    memory = ConversationMemory(memory_type="buffer", max_messages=4)
    with pytest.raises(ValueError, match="missing required keys"):
        memory.load_state(messages=[{"role": "user"}])


def test_load_state_skips_malformed_episodic_entries():
    memory = ConversationMemory(memory_type="buffer", max_messages=4)
    memory.load_state(
        messages=[],
        episodic_memories=[{"summary": "valid episode"}, "not a dict", {"no_summary": True}],
    )
    assert len(memory.episodic_memories) == 1
    assert memory.episodic_memories[0]["summary"] == "valid episode"


def test_session_manager_atomic_write_survives_on_reload(tmp_path: Path):
    manager = SessionManager(session_dir=tmp_path)
    manager.save_session("safe_write", {"messages": [{"role": "user", "content": "hello"}]})
    restored = manager.load_session("safe_write")
    assert restored["messages"][0]["content"] == "hello"


def test_session_manager_handles_corrupt_file(tmp_path: Path):
    corrupt_file = tmp_path / "bad_session.json"
    corrupt_file.write_text("{ this is not valid JSON >>>", encoding="utf-8")
    manager = SessionManager(session_dir=tmp_path)
    result = manager.load_session("bad_session")
    assert result == {}
    assert (tmp_path / "bad_session.corrupt.json").exists()


def test_deterministic_replay_multi_turn():
    memory = ConversationMemory(memory_type="summary", max_messages=4, max_summary_chars=300)
    turns = [
        ("user", "What is a SQL injection?"),
        ("assistant", "SQL injection inserts malicious SQL via input fields."),
        ("user", "How do I prevent it?"),
        ("assistant", "Use parameterised queries and input validation."),
        ("user", "Any tools to scan for it?"),
        ("assistant", "Severity: high\nSource: OWASP\nRecommended Actions:\n- Use sqlmap"),
    ]
    for role, content in turns:
        memory.add_turn(role, content)
    state = memory.get_state()

    memory2 = ConversationMemory(memory_type="summary", max_messages=4, max_summary_chars=300)
    memory2.load_state(
        messages=state["messages"],
        running_summary=state["running_summary"],
        episodic_memories=state["episodic_memories"],
        semantic_facts=state["semantic_facts"],
    )
    assert memory2.messages == memory.messages
    assert memory2.running_summary == memory.running_summary


# ------------------------------------------------------------------
# Stage 2 — BM25 scoring and recall quality
# ------------------------------------------------------------------

def test_bm25_scores_higher_for_repeated_query_terms():
    corpus = [
        ["failed", "brute", "force", "attempt"],
        ["failed", "login", "brute", "force"],
    ]
    query = ["failed", "login"]
    n = len(corpus)
    avg_doc_len = sum(len(d) for d in corpus) / n
    idf_map = {
        term: ConversationMemory._bm25_idf(
            sum(1 for d in corpus if term in set(d)), n
        )
        for term in set(query)
    }
    score_a = ConversationMemory._bm25_doc_score(query, corpus[0], idf_map, avg_doc_len)
    score_b = ConversationMemory._bm25_doc_score(query, corpus[1], idf_map, avg_doc_len)
    assert score_b > score_a, (
        f"Expected doc with both query terms ({score_b:.4f}) to score higher "
        f"than doc with one query term ({score_a:.4f})"
    )


def test_recall_returns_more_relevant_item_first():
    memory = ConversationMemory(memory_type="buffer", max_messages=6, recall_top_k=3)
    memory.update_long_term_from_turn(
        "Analysed ransomware beacon to C2 server",
        "Severity: critical\nSource: VirusTotal\nIOC: 192.168.1.99",
    )
    memory.update_long_term_from_turn(
        "Review patch schedule for web servers",
        "Recommended Actions:\n- Apply CVE-2024-1234 patch",
    )
    recalled = memory.retrieve_relevant_memories("ransomware C2 IOC analysis")
    assert recalled
    assert "ransomware" in recalled[0].lower() or "ioc" in recalled[0].lower()


def test_recall_deduplicates_near_identical_entries():
    memory = ConversationMemory(memory_type="buffer", max_messages=10, recall_top_k=5)
    for _ in range(4):
        memory.add_episodic_memory(
            "Severity: high — repeated brute force on /api/login",
            tags=["auth"],
        )
    recalled = memory.retrieve_relevant_memories("brute force login")
    first_60 = [r[:60].lower() for r in recalled]
    assert len(first_60) == len(set(first_60))


def test_recency_boost_prefers_later_episodes():
    memory = ConversationMemory(memory_type="buffer", max_messages=10, recall_top_k=2)
    memory.add_episodic_memory("phishing email detected on endpoint A", tags=["phishing"])
    for _ in range(5):
        memory.add_episodic_memory("unrelated log noise — disk health check", tags=["general"])
    memory.add_episodic_memory(
        "phishing email detected on endpoint B — more recent", tags=["phishing"]
    )
    recalled = memory.retrieve_relevant_memories("phishing email endpoint")
    assert recalled
    assert "endpoint b" in recalled[0].lower() or "more recent" in recalled[0].lower()


# ------------------------------------------------------------------
# Stage 3 — drift control and context size
# ------------------------------------------------------------------

def test_summary_compression_is_human_readable():
    memory = ConversationMemory(memory_type="summary", max_messages=2, max_summary_chars=500)
    memory.add_turn("user", "Tell me about the recent phishing campaign targeting finance staff.")
    memory.add_turn(
        "assistant",
        "The campaign used spoofed CFO emails. Severity: high. Recommended actions: block sender domain.",
    )
    memory.add_turn("user", "What IOCs were found?")
    assert "---" in memory.running_summary or "user:" in memory.running_summary.lower()
    assert memory.running_summary
    assert "|" not in memory.running_summary


def test_render_context_respects_size_cap():
    memory = ConversationMemory(memory_type="buffer", max_messages=10, recall_top_k=3)
    for i in range(10):
        memory.add_turn("user", f"Message {i}: " + "x" * 300)
        memory.add_turn("assistant", f"Answer {i}: " + "y" * 300)
    context = memory.render_context(query="test")
    assert len(context) <= memory.max_context_chars + 100


def test_context_contains_trim_marker_when_over_limit():
    memory = ConversationMemory(
        memory_type="buffer", max_messages=10, recall_top_k=3, max_context_chars=500
    )
    for i in range(10):
        memory.add_turn("user", "x" * 500)
        memory.add_turn("assistant", "y" * 500)
    context = memory.render_context(query="anything")
    assert "trimmed" in context


def test_stateful_agent_invoke_does_not_crash(tmp_path: Path):
    fake_backend = _FakeBackendAgent()
    agent = G1Agent(
        memory_type="buffer",
        max_messages=4,
        session_id="context_size_test",
        backend_agent=fake_backend,
        verbose=False,
    )
    agent.session_manager = SessionManager(session_dir=tmp_path)
    result = agent.invoke({"input": "Analyze suspicious login"})
    assert "messages" in result


# ------------------------------------------------------------------
# Stage 4 — eval harness
# ------------------------------------------------------------------

def test_eval_recall_hit_rate_passes_on_seeded_memory():
    from src.utils.eval_memory import _make_seeded_memory, evaluate_recall_hit_rate

    memory = _make_seeded_memory()
    probes = [
        ("ransomware C2 beacon", "ransomware"),
        ("failed login VPN", "failed"),
    ]
    rate = evaluate_recall_hit_rate(memory, probes)
    assert rate >= 0.5, f"Recall hit rate too low: {rate}"


def test_eval_session_roundtrip_passes():
    from src.utils.eval_memory import _make_seeded_memory, evaluate_session_roundtrip

    memory = _make_seeded_memory()
    assert evaluate_session_roundtrip(memory)


def test_full_eval_score_above_threshold():
    from src.utils.eval_memory import run_full_eval

    result = run_full_eval()
    assert result.score >= 0.75, f"Memory eval score below 0.75: {result}"