# Benchmark Evaluation Report

- timestamp: `2026-04-08T04:27:24.753520+00:00`
- mode: `real-llm`
- agent_mode: `g1`
- provider: `openai`
- dataset: `/Users/nghiatran/projects/cyber-llm-agent/data/benchmarks/threat_cases.json`
- total_tests: `6`
- average_precision: `1.0`
- average_recall: `0.75`
- average_f1_score: `0.8492`
- average_latency_seconds: `12.0444`

## Per-case metrics

| id | name | precision | recall | f1 | latency_s |
| --- | --- | ---: | ---: | ---: | ---: |
| case_001 | Brute Force Login Pattern | 1.0 | 1.0 | 1.0 | 21.9212 |
| case_002 | Ransomware Indicator | 1.0 | 0.75 | 0.8571 | 9.3879 |
| case_003 | DDoS Traffic Spike | 1.0 | 0.75 | 0.8571 | 10.5284 |
| case_004 | Phishing Campaign | 1.0 | 0.5 | 0.6667 | 9.6046 |
| case_005 | Port Scan Recon | 1.0 | 0.75 | 0.8571 | 10.4252 |
| case_006 | Privilege Escalation Suspicion | 1.0 | 0.75 | 0.8571 | 10.399 |
