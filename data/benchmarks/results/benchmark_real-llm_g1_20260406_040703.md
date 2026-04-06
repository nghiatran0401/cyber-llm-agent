# Benchmark Evaluation Report

- timestamp: `2026-04-06T04:07:03.851757+00:00`
- mode: `real-llm`
- agent_mode: `g1`
- provider: `openai`
- dataset: `/Users/nghiatran/projects/cyber-llm-agent/data/benchmarks/threat_cases.json`
- total_tests: `6`
- average_precision: `1.0`
- average_recall: `0.7917`
- average_f1_score: `0.8524`
- average_latency_seconds: `13.3758`

## Per-case metrics

| id | name | precision | recall | f1 | latency_s |
| --- | --- | ---: | ---: | ---: | ---: |
| case_001 | Brute Force Login Pattern | 1.0 | 0.75 | 0.8571 | 44.4413 |
| case_002 | Ransomware Indicator | 1.0 | 1.0 | 1.0 | 8.1012 |
| case_003 | DDoS Traffic Spike | 1.0 | 1.0 | 1.0 | 6.0739 |
| case_004 | Phishing Campaign | 1.0 | 0.25 | 0.4 | 6.4715 |
| case_005 | Port Scan Recon | 1.0 | 1.0 | 1.0 | 7.0111 |
| case_006 | Privilege Escalation Suspicion | 1.0 | 0.75 | 0.8571 | 8.156 |
