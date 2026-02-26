"""Reporting and artifact IO for benchmark runs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def render_markdown(report: Dict[str, Any]) -> str:
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


def write_artifacts(output_dir: Path, report: Dict[str, Any]) -> Dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base_name = f"benchmark_{report['benchmark_mode']}_{report['agent_mode']}_{run_stamp}"
    json_path = output_dir / f"{base_name}.json"
    md_path = output_dir / f"{base_name}.md"
    latest_json = output_dir / "latest.json"
    latest_md = output_dir / "latest.md"

    markdown = render_markdown(report)
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


def load_latest_report(output_dir: Path) -> Dict[str, Any]:
    latest_json = output_dir / "latest.json"
    if not latest_json.exists():
        raise FileNotFoundError(f"No latest benchmark report found at {latest_json}.")
    return json.loads(latest_json.read_text(encoding="utf-8"))
