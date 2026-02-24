"""Unit tests for prompt versioning and A/B flow."""

from src.utils.prompt_manager import PromptManager


class _FakeAgent:
    def run(self, prompt: str) -> str:
        text = prompt.lower()
        if "evidence-first" in text:
            return "Indicators found. Threat assessment: high. Recommended actions: block ip."
        return "High risk brute force. Block ip."


def test_list_prompt_versions_reads_prefix():
    manager = PromptManager()
    versions = manager.list_prompt_versions()
    assert "security_analysis_v1.txt" in versions
    assert "security_analysis_v2.txt" in versions


def test_run_ab_test_returns_best_variant():
    manager = PromptManager()
    cases = [
        {
            "id": "1",
            "name": "Brute force sample",
            "log": "Failed SSH login repeated from same IP.",
            "expected_keywords": ["high", "block ip"],
        }
    ]
    result = manager.run_ab_test(
        agent=_FakeAgent(),
        variant_to_prompt_file={
            "v1": "security_analysis_v1.txt",
            "v2": "security_analysis_v2.txt",
        },
        test_cases=cases,
    )
    assert result["best_variant"] in {"v1", "v2"}
    assert "variants" in result

