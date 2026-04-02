# Benchmark Evaluation Methodology

This document defines how benchmark evaluation is executed and how results should be used for Option D evidence.

## Objectives

- Provide repeatable evaluation for cybersecurity-agent behavior.
- Keep CI evaluation lightweight and deterministic.
- Support real-LLM staging runs for demonstration and report evidence.

## Dataset

- Canonical dataset: `data/benchmarks/threat_cases.json`
- Schema:
  - `id`
  - `name`
  - `log`
  - `expected_keywords`
  - `unexpected_keywords`

## Execution Modes

### 1) Offline mode (default, CI-safe)

- Command: `make benchmark`
- Uses deterministic offline adapter in `src/benchmarking/agents.py`
- Purpose: benchmark pipeline presence and artifact generation

### 2) Real-LLM mode (staging/manual)

- Command:
  - `BENCHMARK_MODE=real-llm BENCHMARK_AGENT_MODE=g1 BENCHMARK_PROVIDER=openai make benchmark`
  - `BENCHMARK_MODE=real-llm BENCHMARK_AGENT_MODE=g2 BENCHMARK_PROVIDER=openai make benchmark`
- Uses real runtime paths:
  - G1: `run_g1_analysis(...)`
  - G2: `run_g2_analysis(...)`
- Required environment:
  - `OPENAI_API_KEY`
  - `OTX_API_KEY`

## Metrics

Computed by `src/benchmarking/evaluator.py`:

- `precision`
- `recall`
- `f1_score`
- `latency_seconds`
- `tokens_approx`

Aggregate outputs:

- `average_precision`
- `average_recall`
- `average_f1_score`
- `average_latency_seconds`
- `total_tests`

## Artifacts

Every benchmark run writes:

- `data/benchmarks/results/latest.json`
- `data/benchmarks/results/latest.md`
- Timestamped JSON/Markdown snapshots in the same directory

Human-readable summary command:

- `make benchmark-report`

## CI Integration

The CI workflow includes a named `Benchmark evaluation` step that runs `make benchmark` in offline mode.

- This is a presence-only gate.
- The job fails only if benchmark execution itself fails.
- Metric thresholds are intentionally not enforced yet.

## Option D Evidence Mapping

Use benchmark artifacts in project documentation to support:

- evaluation against benchmark datasets,
- analysis/discussion of experimental results,
- demonstration scenarios for G1 and G2.

Recommended report attachment per milestone:

1. latest benchmark markdown summary,
2. one timestamped JSON artifact,
3. short interpretation notes (what improved/regressed and why).
