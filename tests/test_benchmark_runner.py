"""Unit tests for scripts/run_benchmark.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import run_benchmark
from src.benchmarking.evaluator import AgentEvaluator


def test_load_dataset_reads_test_cases(tmp_path: Path):
    dataset = tmp_path / "cases.json"
    dataset.write_text(
        json.dumps(
            {
                "test_cases": [
                    {
                        "id": "case_001",
                        "name": "Demo",
                        "log": "Failed SSH login from 10.0.0.1 repeated 12 times.",
                        "expected_keywords": ["brute force"],
                        "unexpected_keywords": ["normal traffic"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    loaded = run_benchmark._load_dataset(dataset)
    assert isinstance(loaded, list)
    assert loaded[0]["id"] == "case_001"


def test_load_dataset_rejects_non_list_test_cases(tmp_path: Path):
    dataset = tmp_path / "bad_cases.json"
    dataset.write_text(json.dumps({"test_cases": {"bad": "shape"}}), encoding="utf-8")

    with pytest.raises(ValueError, match="must be a list"):
        run_benchmark._load_dataset(dataset)


def test_normalize_cases_applies_limit_and_skips_empty_logs():
    raw_cases = [
        {
            "id": "case_001",
            "name": "Valid",
            "log": "Inbound HTTP requests jumped to 9 million per minute.",
            "expected_keywords": ["ddos"],
            "unexpected_keywords": [],
        },
        {
            "id": "case_002",
            "name": "Invalid",
            "log": "   ",
            "expected_keywords": [],
            "unexpected_keywords": [],
        },
    ]

    normalized = run_benchmark._normalize_cases(raw_cases, case_limit=2)
    assert len(normalized) == 1
    assert normalized[0]["id"] == "case_001"
    assert "Security log/event:" in normalized[0]["prompt"]
    assert normalized[0]["source_log"].startswith("Inbound HTTP requests")


def test_write_artifacts_and_load_latest_report(tmp_path: Path):
    report = {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "benchmark_mode": "offline",
        "agent_mode": "g1",
        "provider": "openai",
        "dataset": "/tmp/threat_cases.json",
        "total_tests": 1,
        "average_precision": 1.0,
        "average_recall": 1.0,
        "average_f1_score": 1.0,
        "average_latency_seconds": 0.0,
        "results": [],
    }

    written = run_benchmark._write_artifacts(tmp_path, report)
    assert Path(written["json"]).exists()
    assert Path(written["markdown"]).exists()
    assert Path(written["latest_json"]).exists()
    assert Path(written["latest_markdown"]).exists()

    latest = run_benchmark._load_latest_report(tmp_path)
    assert latest["benchmark_mode"] == "offline"
    assert latest["total_tests"] == 1


def test_offline_agent_and_evaluator_end_to_end():
    cases = run_benchmark._normalize_cases(
        [
            {
                "id": "case_001",
                "name": "Brute",
                "log": "Failed SSH login from 203.0.113.9 repeated 14 times in 2 minutes.",
                "expected_keywords": ["brute force", "high", "failed login", "block ip"],
                "unexpected_keywords": ["normal traffic"],
            }
        ],
        case_limit=0,
    )
    evaluator = AgentEvaluator()
    result = evaluator.run_benchmark(run_benchmark._OfflineDeterministicAgent(), cases)

    assert result["total_tests"] == 1
    assert result["average_f1_score"] > 0
    assert result["results"][0]["test_id"] == "case_001"


def test_real_llm_agent_rejects_unsupported_provider():
    with pytest.raises(ValueError, match="provider=ollama is not implemented"):
        run_benchmark._RealLLMBenchmarkAgent(agent_mode="g1", provider="ollama")
