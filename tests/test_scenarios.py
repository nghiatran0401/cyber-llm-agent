"""Scenario-driven tests (offline safe)."""

from src.utils.evaluator import AgentEvaluator


class _FakeScenarioAgent:
    """Small deterministic agent for benchmark tests."""

    def run(self, prompt: str) -> str:
        text = prompt.lower()
        if "ssh" in text or "failed" in text:
            return "High severity brute force attack detected. Recommend block IP and reset credentials."
        if "rename" in text or "entropy" in text:
            return "Critical ransomware indicators found. Isolate host and verify backups."
        if "requests jumped" in text or "botnet" in text:
            return "Likely DDoS attack. Apply rate limiting and upstream mitigation."
        if "spoofed sender" in text:
            return "Phishing campaign detected. Enforce MFA and email filtering."
        if "ports 22" in text:
            return "Reconnaissance port scan observed. Tighten firewall and monitor source."
        if "admin role" in text:
            return "Potential privilege escalation. Audit recent role changes immediately."
        return "No clear threat."


def test_benchmark_suite_runs_with_six_cases():
    cases = [
        {"id": "1", "name": "brute", "prompt": "Failed SSH login repeated.", "expected_keywords": ["brute force", "high"]},
        {"id": "2", "name": "ransom", "prompt": "Mass rename events and entropy.", "expected_keywords": ["ransomware", "critical"]},
        {"id": "3", "name": "ddos", "prompt": "Requests jumped from botnet ranges.", "expected_keywords": ["ddos", "mitigation"]},
        {"id": "4", "name": "phishing", "prompt": "Spoofed sender domain and fake SSO.", "expected_keywords": ["phishing", "mfa"]},
        {"id": "5", "name": "scan", "prompt": "Ports 22, 80, 443 scanned sequentially.", "expected_keywords": ["port scan", "firewall"]},
        {"id": "6", "name": "priv esc", "prompt": "Admin role granted off hours.", "expected_keywords": ["privilege escalation", "audit"]},
    ]
    evaluator = AgentEvaluator()
    result = evaluator.run_benchmark(_FakeScenarioAgent(), cases)

    assert result["total_tests"] == 6
    assert result["average_precision"] >= 0.5
    assert result["average_recall"] >= 0.5
    assert result["average_latency_seconds"] >= 0.0

