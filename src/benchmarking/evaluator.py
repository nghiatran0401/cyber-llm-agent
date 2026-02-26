"""Evaluation helpers for benchmark and refinement."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List


class AgentEvaluator:
    """Compute simple quality and latency metrics for agent outputs."""

    def evaluate_response(
        self,
        response: str,
        expected_keywords: List[str],
        unexpected_keywords: List[str] | None = None,
    ) -> Dict[str, Any]:
        """Evaluate response text using keyword-oriented metrics."""
        normalized = (response or "").lower()
        expected = [kw.lower() for kw in expected_keywords]
        unexpected = [kw.lower() for kw in (unexpected_keywords or [])]

        tp = sum(1 for kw in expected if kw in normalized)
        fn = max(0, len(expected) - tp)
        fp = sum(1 for kw in unexpected if kw in normalized)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1_score, 4),
            "true_positive_keywords": tp,
            "false_positive_keywords": fp,
            "missing_expected_keywords": fn,
            "response_length": len(response or ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def measure_latency(self, agent: Any, prompt: str) -> Dict[str, Any]:
        """Measure single prompt latency against an agent."""
        start = time.perf_counter()
        response = self._invoke_agent(agent, prompt)
        latency = time.perf_counter() - start
        return {
            "latency_seconds": round(latency, 4),
            "response": response,
            "tokens_approx": len((response or "").split()),
        }

    def run_benchmark(self, agent: Any, test_cases: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run benchmark suite and compute aggregate metrics."""
        results: List[Dict[str, Any]] = []
        total_latency = 0.0

        for idx, case in enumerate(test_cases, start=1):
            prompt = case.get("prompt", "")
            expected = case.get("expected_keywords", [])
            unexpected = case.get("unexpected_keywords", [])

            latency_result = self.measure_latency(agent, prompt)
            total_latency += latency_result["latency_seconds"]
            metrics = self.evaluate_response(latency_result["response"], expected, unexpected)
            metrics["latency_seconds"] = latency_result["latency_seconds"]
            metrics["tokens_approx"] = latency_result["tokens_approx"]

            results.append(
                {
                    "test_id": case.get("id", f"case_{idx:03d}"),
                    "test_name": case.get("name", f"Case {idx}"),
                    "prompt": prompt,
                    "response": latency_result["response"],
                    "metrics": metrics,
                }
            )

        total = len(results) or 1
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_tests": len(results),
            "average_precision": round(sum(r["metrics"]["precision"] for r in results) / total, 4),
            "average_recall": round(sum(r["metrics"]["recall"] for r in results) / total, 4),
            "average_f1_score": round(sum(r["metrics"]["f1_score"] for r in results) / total, 4),
            "average_latency_seconds": round(total_latency / total, 4),
            "results": results,
        }

    def evaluate_rubric(
        self,
        response: str,
        rubric: Dict[str, List[str]] | None = None,
    ) -> Dict[str, Any]:
        """Score response quality against lightweight rubric checks."""
        content = (response or "").lower()
        criteria = rubric or {
            "evidence": ["source:", "#chunk-", "indicator", "evidence"],
            "severity": ["severity", "critical", "high", "medium", "low"],
            "actions": ["recommended", "contain", "block", "isolate", "monitor", "remediation"],
            "clarity": ["summary", "threat", "assessment", "next steps"],
        }
        checks: Dict[str, bool] = {}
        score_points = 0
        for name, keywords in criteria.items():
            passed = any(keyword in content for keyword in keywords)
            checks[name] = passed
            if passed:
                score_points += 1

        max_points = max(1, len(criteria))
        rubric_score = round((score_points / max_points) * 5, 2)
        if rubric_score >= 4.0:
            label = "strong"
        elif rubric_score >= 2.5:
            label = "acceptable"
        else:
            label = "weak"

        return {
            "rubric_score": rubric_score,
            "rubric_label": label,
            "checks": checks,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def _invoke_agent(agent: Any, prompt: str) -> str:
        """Invoke agent across common interfaces and normalize to text."""
        if hasattr(agent, "run"):
            return str(agent.run(prompt))

        if hasattr(agent, "invoke"):
            result = agent.invoke({"input": prompt})
            if isinstance(result, dict):
                if "output" in result:
                    return str(result["output"])
                if "messages" in result and result["messages"]:
                    last = result["messages"][-1]
                    if hasattr(last, "content"):
                        return str(last.content)
                    if isinstance(last, tuple) and len(last) == 2:
                        return str(last[1])
                    return str(last)
            if hasattr(result, "content"):
                return str(result.content)
            return str(result)

        raise TypeError("Agent must provide run() or invoke().")
