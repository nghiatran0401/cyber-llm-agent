#!/usr/bin/env python3
"""CI test reporter: reads pytest output from stdin and prints a summary with owner/severity."""

import re
import sys

OWNER_MAP = {
    "test_api_endpoints": "API / platform",
    "test_evaluator": "API / platform",
    "test_benchmark_runner": "API / platform",
    "test_scenarios": "API / platform",
    "test_multiagent": "G2 / multiagent",
    "test_g1_service": "G1 / ReAct runtime",
    "test_state_validator": "G1 / ReAct runtime",
    "test_prompt_manager": "G1 / ReAct runtime",
    "test_rag_tools": "RAG",
    "test_memory": "Memory / sessions",
    "test_tools": "Tools (CTI, log parser)",
    "test_sandbox": "Sandbox",
    "test_agent_flow": "Integration (agent + tools)",
}

SEVERITY_MAP = {
    "test_api_endpoints": "HIGH",
    "test_multiagent": "HIGH",
    "test_g1_service": "HIGH",
    "test_memory": "HIGH",
    "test_tools": "MEDIUM",
    "test_sandbox": "MEDIUM",
    "test_rag_tools": "MEDIUM",
    "test_evaluator": "MEDIUM",
    "test_state_validator": "LOW",
    "test_prompt_manager": "LOW",
    "test_benchmark_runner": "LOW",
    "test_scenarios": "LOW",
}

FAIL_PATTERN = re.compile(r"FAILED\s+(\S+)::(\S+)")
COLLECTION_ERROR_MARKERS = (
    "ERROR collecting",
    "errors during collection",
    "Interrupted:",
)


def main():
    lines = sys.stdin.read()
    print(lines)

    if any(m in lines for m in COLLECTION_ERROR_MARKERS):
        print("\n--- CI Report: Collection or run errors detected ---")
        sys.exit(1)

    failures = FAIL_PATTERN.findall(lines)
    if not failures:
        print("\n--- CI Report: All tests passed ---")
        sys.exit(0)

    print("\n--- CI Report: Failures Detected ---")
    print(f"{'File':<45} {'Test':<55} {'Owner':<35} {'Severity'}")
    print("-" * 140)
    for filepath, test_name in failures:
        module = filepath.split("/")[-1].replace(".py", "")
        owner = OWNER_MAP.get(module, "Unknown")
        severity = SEVERITY_MAP.get(module, "UNKNOWN")
        print(f"{filepath:<45} {test_name:<55} {owner:<35} {severity}")

    print(f"\nTotal failures: {len(failures)}")
    sys.exit(1)


if __name__ == "__main__":
    main()
