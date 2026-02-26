"""Run benchmark evaluation against canonical threat cases dataset."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from src.benchmarking.agents import OfflineDeterministicAgent, RealLLMBenchmarkAgent
from src.benchmarking.evaluator import AgentEvaluator
from src.benchmarking.reporting import load_latest_report, render_markdown, write_artifacts
from src.config.settings import Settings
from src.utils.prompt_templates import render_prompt_template


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run benchmark evaluation suite.")
    parser.add_argument(
        "--mode",
        choices=("offline", "real-llm"),
        default="offline",
        help="Benchmark execution mode.",
    )
    parser.add_argument(
        "--agent-mode",
        choices=("g1", "g2"),
        default="g1",
        help="Agent mode used for real-llm benchmark runs.",
    )
    parser.add_argument(
        "--provider",
        choices=("openai", "ollama"),
        default="openai",
        help="LLM provider for real-llm mode. Ollama reserved for future extension.",
    )
    parser.add_argument(
        "--dataset",
        default=str(Settings.BENCHMARKS_DIR / "threat_cases.json"),
        help="Path to benchmark dataset JSON file.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(Settings.BENCHMARKS_DIR / "results"),
        help="Directory for benchmark output artifacts.",
    )
    parser.add_argument(
        "--case-limit",
        type=int,
        default=0,
        help="Optional limit on number of cases to run (0 means all).",
    )
    parser.add_argument(
        "--report-from-latest",
        action="store_true",
        help="Render markdown report from output-dir/latest.json without running benchmark.",
    )
    return parser.parse_args()


def load_dataset(dataset_path: Path) -> List[Dict[str, Any]]:
    payload = json.loads(dataset_path.read_text(encoding="utf-8"))
    cases = payload.get("test_cases", [])
    if not isinstance(cases, list):
        raise ValueError("Dataset field 'test_cases' must be a list.")
    return cases


def build_prompt(log_text: str) -> str:
    return render_prompt_template(
        "benchmark/eval_prompt.txt",
        log_text=log_text,
    )


def normalize_cases(raw_cases: List[Dict[str, Any]], case_limit: int) -> List[Dict[str, Any]]:
    selected = raw_cases[:case_limit] if case_limit > 0 else raw_cases
    normalized: List[Dict[str, Any]] = []
    for idx, case in enumerate(selected, start=1):
        log_text = str(case.get("log", "")).strip()
        if not log_text:
            continue
        normalized.append(
            {
                "id": str(case.get("id", f"case_{idx:03d}")),
                "name": str(case.get("name", f"Case {idx}")),
                "prompt": build_prompt(log_text),
                "expected_keywords": list(case.get("expected_keywords", [])),
                "unexpected_keywords": list(case.get("unexpected_keywords", [])),
                "source_log": log_text,
            }
        )
    if not normalized:
        raise ValueError("No benchmark cases available after normalization.")
    return normalized


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir).resolve()

    if args.report_from_latest:
        latest = load_latest_report(output_dir)
        print(render_markdown(latest))
        return 0

    dataset_path = Path(args.dataset).resolve()
    raw_cases = load_dataset(dataset_path)
    cases = normalize_cases(raw_cases, case_limit=max(0, args.case_limit))

    if args.mode == "offline":
        agent = OfflineDeterministicAgent()
    else:
        agent = RealLLMBenchmarkAgent(agent_mode=args.agent_mode, provider=args.provider)

    evaluator = AgentEvaluator()
    benchmark_result = evaluator.run_benchmark(agent=agent, test_cases=cases)
    report = {
        **benchmark_result,
        "benchmark_mode": args.mode,
        "agent_mode": args.agent_mode,
        "provider": args.provider,
        "dataset": str(dataset_path),
    }
    written = write_artifacts(output_dir=output_dir, report=report)

    print(
        "Benchmark completed: total_tests={total} avg_f1={f1} avg_latency={latency}s".format(
            total=report["total_tests"],
            f1=report["average_f1_score"],
            latency=report["average_latency_seconds"],
        )
    )
    print(f"Artifacts: {written['json']} | {written['markdown']}")
    print(f"Latest: {written['latest_json']} | {written['latest_markdown']}")
    return 0
