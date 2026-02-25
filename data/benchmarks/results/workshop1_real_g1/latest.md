# Benchmark Evaluation Report

- timestamp: `2026-02-25T03:26:39.633016+00:00`
- mode: `real-llm`
- agent_mode: `g1`
- provider: `openai`
- dataset: `/Users/nghiatran/projects/cyber-llm-agent/data/benchmarks/threat_cases_workshop1.json`
- total_tests: `4`
- average_precision: `0.9167`
- average_recall: `0.5917`
- average_f1_score: `0.7079`
- average_latency_seconds: `6.0465`

## Per-case metrics

| id | name | precision | recall | f1 | latency_s |
| --- | --- | ---: | ---: | ---: | ---: |
| wk1_case_001 | Phishing Email with SPF/DMARC Failure | 1.0 | 0.6667 | 0.8 | 8.2283 |
| wk1_case_002 | Phishing Variant with Lookalike Branding | 1.0 | 0.8 | 0.8889 | 5.4087 |
| wk1_case_003 | Benign Newsletter Control Sample | 0.6667 | 0.5 | 0.5714 | 5.0198 |
| wk1_case_004 | Suspicious Newly Registered Domains | 1.0 | 0.4 | 0.5714 | 5.5294 |
