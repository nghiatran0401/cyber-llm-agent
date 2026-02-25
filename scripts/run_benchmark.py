"""Run benchmark evaluation against canonical threat cases dataset."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

# Ensure repository root is importable when executed as a script.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config.settings import Settings
from src.utils.evaluator import AgentEvaluator


def _parse_args() -> argparse.Namespace:
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


def _load_dataset(dataset_path: Path) -> List[Dict[str, Any]]:
    payload = json.loads(dataset_path.read_text(encoding="utf-8"))
    cases = payload.get("test_cases", [])
    if not isinstance(cases, list):
        raise ValueError("Dataset field 'test_cases' must be a list.")
    return cases


def _build_prompt(log_text: str) -> str:
    return (
        "You are a SOC analyst. Analyze this security event and provide:\n"
        "1) threat type\n2) severity\n3) immediate defensive actions\n4) evidence-based rationale.\n\n"
        f"Security log/event:\n{log_text}\n\n"
        "Answer concisely and include concrete actions."
    )


def _normalize_cases(raw_cases: List[Dict[str, Any]], case_limit: int) -> List[Dict[str, Any]]:
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
                "prompt": _build_prompt(log_text),
                "expected_keywords": list(case.get("expected_keywords", [])),
                "unexpected_keywords": list(case.get("unexpected_keywords", [])),
                "source_log": log_text,
            }
        )
    if not normalized:
        raise ValueError("No benchmark cases available after normalization.")
    return normalized


class _OfflineDeterministicAgent:
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


class _RealLLMBenchmarkAgent:
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


def _render_markdown(report: Dict[str, Any]) -> str:
    lines: List[str] = [
        "# Benchmark Evaluation Report",
        "",
        f"- timestamp: `{report['timestamp']}`",
        f"- mode: `{report['benchmark_mode']}`",
        f"- agent_mode: `{report['agent_mode']}`",
        f"- provider: `{report['provider']}`",
        f"- dataset: `{report['dataset']}`",
        f"- total_tests: `{report['total_tests']}`",
        f"- average_precision: `{report['average_precision']}`",
        f"- average_recall: `{report['average_recall']}`",
        f"- average_f1_score: `{report['average_f1_score']}`",
        f"- average_latency_seconds: `{report['average_latency_seconds']}`",
        "",
        "## Per-case metrics",
        "",
        "| id | name | precision | recall | f1 | latency_s |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for case in report.get("results", []):
        metrics = case.get("metrics", {})
        lines.append(
            "| {id} | {name} | {precision} | {recall} | {f1} | {latency} |".format(
                id=case.get("test_id", "n/a"),
                name=case.get("test_name", "n/a"),
                precision=metrics.get("precision", 0.0),
                recall=metrics.get("recall", 0.0),
                f1=metrics.get("f1_score", 0.0),
                latency=metrics.get("latency_seconds", 0.0),
            )
        )
    return "\n".join(lines) + "\n"


def _write_artifacts(output_dir: Path, report: Dict[str, Any]) -> Dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base_name = f"benchmark_{report['benchmark_mode']}_{report['agent_mode']}_{run_stamp}"
    json_path = output_dir / f"{base_name}.json"
    md_path = output_dir / f"{base_name}.md"
    latest_json = output_dir / "latest.json"
    latest_md = output_dir / "latest.md"

    markdown = _render_markdown(report)
    json_blob = json.dumps(report, ensure_ascii=True, indent=2)

    json_path.write_text(json_blob, encoding="utf-8")
    md_path.write_text(markdown, encoding="utf-8")
    latest_json.write_text(json_blob, encoding="utf-8")
    latest_md.write_text(markdown, encoding="utf-8")
    return {
        "json": str(json_path),
        "markdown": str(md_path),
        "latest_json": str(latest_json),
        "latest_markdown": str(latest_md),
    }


def _load_latest_report(output_dir: Path) -> Dict[str, Any]:
    latest_json = output_dir / "latest.json"
    if not latest_json.exists():
        raise FileNotFoundError(f"No latest benchmark report found at {latest_json}.")
    return json.loads(latest_json.read_text(encoding="utf-8"))


def main() -> int:
    args = _parse_args()
    output_dir = Path(args.output_dir).resolve()

    if args.report_from_latest:
        latest = _load_latest_report(output_dir)
        print(_render_markdown(latest))
        return 0

    dataset_path = Path(args.dataset).resolve()
    raw_cases = _load_dataset(dataset_path)
    cases = _normalize_cases(raw_cases, case_limit=max(0, args.case_limit))

    if args.mode == "offline":
        agent = _OfflineDeterministicAgent()
    else:
        agent = _RealLLMBenchmarkAgent(agent_mode=args.agent_mode, provider=args.provider)

    evaluator = AgentEvaluator()
    benchmark_result = evaluator.run_benchmark(agent=agent, test_cases=cases)
    report = {
        **benchmark_result,
        "benchmark_mode": args.mode,
        "agent_mode": args.agent_mode,
        "provider": args.provider,
        "dataset": str(dataset_path),
    }
    written = _write_artifacts(output_dir=output_dir, report=report)

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


if __name__ == "__main__":
    raise SystemExit(main())
