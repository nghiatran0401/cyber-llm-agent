"""Memory quality evaluator — run as a script or import in CI."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

from src.utils.memory_manager import ConversationMemory


@dataclass
class MemoryEvalResult:
    recall_hit_rate: float = 0.0
    context_size_ok: bool = True
    summary_readable: bool = True
    session_roundtrip_ok: bool = True
    details: List[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        checks = [
            self.recall_hit_rate,
            1.0 if self.context_size_ok else 0.0,
            1.0 if self.summary_readable else 0.0,
            1.0 if self.session_roundtrip_ok else 0.0,
        ]
        return round(sum(checks) / len(checks), 3)

    def __str__(self) -> str:
        return (
            f"MemoryEvalResult(score={self.score}, "
            f"recall_hit_rate={self.recall_hit_rate:.2f}, "
            f"context_size_ok={self.context_size_ok}, "
            f"summary_readable={self.summary_readable}, "
            f"session_roundtrip_ok={self.session_roundtrip_ok})"
        )


def _make_seeded_memory(max_messages: int = 8) -> ConversationMemory:
    memory = ConversationMemory(memory_type="summary", max_messages=max_messages, recall_top_k=3)
    turns: List[Tuple[str, str]] = [
        ("user", "Investigate ransomware beacon to 10.0.0.1"),
        ("assistant", "Severity: critical\nSource: AlienVault\nIOC: 10.0.0.1"),
        ("user", "Check failed logins on VPN gateway"),
        ("assistant", "Severity: high\n- 400 failed SSH attempts from 185.0.0.2"),
        ("user", "Scan for SQL injection in /api/login"),
        ("assistant", "Severity: medium\n- Payload detected in username field"),
        ("user", "What is the patch status for CVE-2024-1234?"),
        ("assistant", "Unpatched on 3 hosts. Recommended Actions:\n- Apply vendor patch"),
        ("user", "Summarise today's findings"),
        ("assistant", "Four incidents: ransomware C2, VPN brute-force, SQLi, unpatched CVE."),
    ]
    for role, content in turns:
        memory.add_turn(role, content)
    for role, content in turns:
        memory.update_long_term_from_turn(content, content)
    return memory


def evaluate_recall_hit_rate(memory: ConversationMemory, probes: List[Tuple[str, str]]) -> float:
    """Fraction of probes where at least one recalled item contains the expected keyword."""
    if not probes:
        return 1.0
    hits = 0
    for query, expected_keyword in probes:
        recalled = memory.retrieve_relevant_memories(query)
        if any(expected_keyword.lower() in item.lower() for item in recalled):
            hits += 1
    return hits / len(probes)


def evaluate_context_size(memory: ConversationMemory) -> bool:
    context = memory.render_context(query="ransomware IOC")
    return len(context) <= getattr(memory, "MAX_CONTEXT_CHARS", 4000) + 200


def evaluate_summary_readability(memory: ConversationMemory) -> bool:
    if not memory.running_summary:
        return True
    # Must not be a raw pipe-wall and must contain at least one colon (role: content)
    pipes = memory.running_summary.count("|")
    colons = memory.running_summary.count(":")
    return pipes < 5 and colons >= 1


def evaluate_session_roundtrip(memory: ConversationMemory) -> bool:
    state = memory.get_state()
    memory2 = ConversationMemory(
        memory_type=state["memory_type"],
        max_messages=state["max_messages"],
        recall_top_k=state["recall_top_k"],
    )
    try:
        memory2.load_state(
            messages=state["messages"],
            running_summary=state["running_summary"],
            episodic_memories=state["episodic_memories"],
            semantic_facts=state["semantic_facts"],
        )
    except Exception:
        return False
    return memory2.messages == memory.messages and memory2.running_summary == memory.running_summary


def run_full_eval() -> MemoryEvalResult:
    memory = _make_seeded_memory()
    result = MemoryEvalResult()

    probes = [
        ("ransomware C2 beacon", "ransomware"),
        ("failed login brute force VPN", "failed"),
        ("SQL injection api login", "sql"),
        ("CVE patch unpatched hosts", "patch"),
    ]
    result.recall_hit_rate = evaluate_recall_hit_rate(memory, probes)
    result.context_size_ok = evaluate_context_size(memory)
    result.summary_readable = evaluate_summary_readability(memory)
    result.session_roundtrip_ok = evaluate_session_roundtrip(memory)

    if result.recall_hit_rate < 0.75:
        result.details.append(f"Recall hit rate below threshold: {result.recall_hit_rate:.2f}")
    if not result.context_size_ok:
        result.details.append("render_context() exceeds MAX_CONTEXT_CHARS")
    if not result.summary_readable:
        result.details.append("Running summary looks unreadable (pipe-wall pattern)")
    if not result.session_roundtrip_ok:
        result.details.append("Session roundtrip failed — state mismatch after load_state()")

    return result


if __name__ == "__main__":
    result = run_full_eval()
    print(result)
    for detail in result.details:
        print(f"  WARNING: {detail}")
    raise SystemExit(0 if result.score >= 0.75 else 1)