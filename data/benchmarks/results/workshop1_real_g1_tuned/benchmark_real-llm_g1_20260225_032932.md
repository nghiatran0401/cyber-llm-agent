# Benchmark Evaluation Report

- timestamp: `2026-02-25T03:29:32.401236+00:00`
- mode: `real-llm`
- agent_mode: `g1`
- provider: `openai`
- dataset: `/Users/nghiatran/projects/cyber-llm-agent/data/benchmarks/threat_cases_workshop1.json`
- total_tests: `12`
- average_precision: `0.9583`
- average_recall: `0.7125`
- average_f1_score: `0.7818`
- average_latency_seconds: `5.1922`

## Per-case metrics

| id | name | precision | recall | f1 | latency_s |
| --- | --- | ---: | ---: | ---: | ---: |
| wk1_case_001 | Phishing Email with SPF/DMARC Failure | 1.0 | 1.0 | 1.0 | 5.9602 |
| wk1_case_002 | Phishing Variant with Lookalike Branding | 0.8333 | 1.0 | 0.9091 | 2.9112 |
| wk1_case_003 | Benign Newsletter Control Sample | 1.0 | 0.75 | 0.8571 | 2.1131 |
| wk1_case_004 | Suspicious Newly Registered Domains | 1.0 | 1.0 | 1.0 | 3.0366 |
| wk1_case_005 | Credential Leak Mention and ATO Risk | 1.0 | 1.0 | 1.0 | 8.0226 |
| wk1_case_006 | Burst of Failed Logins from Automation Clients | 1.0 | 0.8 | 0.8889 | 6.2458 |
| wk1_case_007 | MFA Friction Followed by Single Success | 1.0 | 1.0 | 1.0 | 6.3232 |
| wk1_case_008 | NFC Relay Suspicion Across Multiple Cities | 1.0 | 0.4 | 0.5714 | 5.3959 |
| wk1_case_009 | Elevated POS NFC Duration Pattern | 0.6667 | 0.4 | 0.5 | 9.296 |
| wk1_case_010 | Device Location Contradiction with Customer Statement | 1.0 | 0.2 | 0.3333 | 5.3028 |
| wk1_case_011 | Airport Check-In Correlated with Fraud Window | 1.0 | 0.6 | 0.75 | 3.642 |
| wk1_case_012 | Mixed Benign and Suspicious NFC Activity | 1.0 | 0.4 | 0.5714 | 4.0573 |
