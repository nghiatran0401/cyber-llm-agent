# Week 5 Evaluation and Prompt Refinement Report

## Scope

This report captures Week 5 deliverables:
- Benchmark scenarios for common cyber threats
- Evaluation metrics (precision, recall, F1, latency)
- Prompt versioning with A/B comparison

## Prompt Versions

- `prompts/security_analysis_v1.txt`: baseline concise security analysis prompt
- `prompts/security_analysis_v2.txt`: evidence-first SOC-style prompt with structured output

## Benchmark Dataset

- File: `data/benchmarks/threat_cases.json`
- Coverage: 6 scenarios (brute force, ransomware, DDoS, phishing, port scan, privilege escalation)
- Each case includes:
  - log text
  - expected keywords
  - unexpected keywords (false-positive hints)

## Metrics Implemented

Implemented in `src/utils/evaluator.py`:
- Precision
- Recall
- F1 score
- Latency (seconds)
- Approximate token count

## A/B Test Workflow

Implemented in `src/utils/prompt_manager.py`:
1. Load prompt variants from `prompts/`
2. Run each variant against shared test cases
3. Compare average F1 and latency
4. Select best variant

## Week 5 Notes

- Tests for evaluator, prompt manager, and scenario benchmark are offline-safe (no API key required).
- This provides a stable foundation for real API benchmarking in later phases.
