"""Prompt versioning and lightweight A/B testing support."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from src.config.settings import Settings
from src.utils.evaluator import AgentEvaluator


class PromptManager:
    """Manage prompt versions stored in prompts/ directory."""

    def __init__(self, prompt_dir: Path | None = None):
        self.prompt_dir = Path(prompt_dir or (Settings.BASE_DIR / "prompts"))
        self.prompt_dir.mkdir(parents=True, exist_ok=True)

    def load_prompt(self, prompt_name: str) -> str:
        """Load prompt content by file name."""
        prompt_path = self.prompt_dir / prompt_name
        if not prompt_path.exists():
            raise FileNotFoundError(f"Prompt file not found: {prompt_path}")
        return prompt_path.read_text(encoding="utf-8")

    def list_prompt_versions(self, prefix: str = "security_analysis_") -> List[str]:
        """List available prompt files sharing a prefix."""
        return sorted(path.name for path in self.prompt_dir.glob(f"{prefix}*.txt"))

    def run_ab_test(
        self,
        agent: Any,
        variant_to_prompt_file: Dict[str, str],
        test_cases: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Run keyword-based A/B test across prompt variants."""
        evaluator = AgentEvaluator()
        summary: Dict[str, Any] = {}

        for label, filename in variant_to_prompt_file.items():
            prompt_template = self.load_prompt(filename)
            cases: List[Dict[str, Any]] = []

            for case in test_cases:
                prompt = f"{prompt_template}\n\nLog: {case['log']}\n\nAnalysis:"
                cases.append(
                    {
                        "id": case.get("id", "case"),
                        "name": case.get("name", "Unnamed case"),
                        "prompt": prompt,
                        "expected_keywords": case.get("expected_keywords", []),
                        "unexpected_keywords": case.get("unexpected_keywords", []),
                    }
                )

            summary[label] = evaluator.run_benchmark(agent, cases)

        best_variant = max(
            summary,
            key=lambda label: (
                summary[label]["average_f1_score"],
                -summary[label]["average_latency_seconds"],
            ),
        )
        return {"best_variant": best_variant, "variants": summary}

