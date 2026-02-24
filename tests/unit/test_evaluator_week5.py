"""Unit tests for Week 5 evaluator metrics."""

from src.utils.evaluator import AgentEvaluator


class _InvokeOnlyAgent:
    def invoke(self, payload):
        return {"output": f"processed: {payload['input']}"}


def test_evaluate_response_computes_precision_recall_f1():
    evaluator = AgentEvaluator()
    metrics = evaluator.evaluate_response(
        response="Brute force attack detected with high severity.",
        expected_keywords=["brute force", "high"],
        unexpected_keywords=["normal traffic"],
    )
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1_score"] == 1.0


def test_measure_latency_supports_invoke_agent():
    evaluator = AgentEvaluator()
    result = evaluator.measure_latency(_InvokeOnlyAgent(), "test prompt")
    assert result["latency_seconds"] >= 0.0
    assert "processed:" in result["response"]


def test_run_benchmark_returns_aggregate_metrics():
    class _RunAgent:
        def run(self, prompt: str):
            return "phishing detected, enable mfa"

    evaluator = AgentEvaluator()
    results = evaluator.run_benchmark(
        _RunAgent(),
        [
            {
                "id": "a",
                "name": "case A",
                "prompt": "suspected phishing",
                "expected_keywords": ["phishing", "mfa"],
                "unexpected_keywords": ["benign"],
            }
        ],
    )

    assert results["total_tests"] == 1
    assert results["average_precision"] >= 0.5
    assert results["average_recall"] >= 0.5

