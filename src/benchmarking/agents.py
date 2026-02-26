"""Agent adapters for benchmark execution modes."""

from __future__ import annotations


class OfflineDeterministicAgent:
    """Deterministic agent for CI-safe benchmark presence checks."""

    def run(self, prompt: str) -> str:
        text = (prompt or "").lower()
        if "failed ssh login" in text or "failed login" in text:
            return (
                "Threat: brute force login pattern.\n"
                "Severity: high.\n"
                "Recommended Actions:\n- block ip\n- enforce mfa\n- monitor failed login spikes"
            )
        if "mass file rename" in text or "entropy" in text:
            return (
                "Threat: ransomware behavior.\n"
                "Severity: critical.\n"
                "Recommended Actions:\n- isolate affected hosts\n- validate backup integrity"
            )
        if "9 million per minute" in text or "botnet" in text:
            return (
                "Threat: ddos traffic spike.\n"
                "Severity: high.\n"
                "Recommended Actions:\n- enable rate limiting\n- activate mitigation profile"
            )
        if "lookalike sso" in text or "spoofed sender" in text:
            return (
                "Threat: phishing campaign.\n"
                "Severity: medium.\n"
                "Recommended Actions:\n- tighten email filter\n- enforce mfa reset messaging"
            )
        if "ports 22, 80, 443, 3389" in text or "sequential connection" in text:
            return (
                "Threat: port scan reconnaissance.\n"
                "Severity: medium.\n"
                "Recommended Actions:\n- update firewall rules\n- monitor reconnaissance behavior"
            )
        if "admin role outside approved change window" in text:
            return (
                "Threat: privilege escalation suspicion.\n"
                "Severity: high.\n"
                "Recommended Actions:\n- investigate account activity\n- audit role assignment trail"
            )
        return "Threat: unknown.\nSeverity: medium.\nRecommended Actions:\n- investigate and monitor."


class RealLLMBenchmarkAgent:
    """Adapter for real G1/G2 runtime execution."""

    def __init__(self, agent_mode: str, provider: str):
        if provider != "openai":
            raise ValueError(
                "provider=ollama is not implemented yet. Use provider=openai for now."
            )
        self.agent_mode = agent_mode

    def run(self, prompt: str) -> str:
        if self.agent_mode == "g1":
            from services.api.service import run_g1_analysis

            response, *_ = run_g1_analysis(prompt, session_id="benchmark_eval")
            return str(response)

        from services.api.service import run_g2_analysis

        result, *_ = run_g2_analysis(prompt)
        return str(result.get("final_report", ""))
