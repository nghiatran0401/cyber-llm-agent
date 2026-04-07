"""Agent adapters for benchmark execution."""

from __future__ import annotations


class RealLLMBenchmarkAgent:
    """Adapter for real G1/G2 runtime execution."""

    def __init__(self, agent_mode: str, provider: str):
        if provider != "openai":
            raise ValueError(
                f"Only provider=openai is supported for benchmarks; got {provider!r}."
            )
        self.agent_mode = agent_mode

    def run(self, prompt: str) -> str:
        if self.agent_mode == "g1":
            from services.api.g1_service import run_g1_analysis

            response, *_ = run_g1_analysis(prompt, session_id="benchmark_eval")
            return str(response)

        from services.api.g2_service import run_g2_analysis

        result, *_ = run_g2_analysis(prompt)
        return str(result.get("final_report", ""))
