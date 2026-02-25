# Benchmark Evaluation Report

- timestamp: `2026-02-25T03:21:01.921466+00:00`
- mode: `offline`
- agent_mode: `g1`
- provider: `openai`
- dataset: `/Users/nghiatran/projects/cyber-llm-agent/data/benchmarks/threat_cases_workshop1.json`
- total_tests: `12`
- average_precision: `0.1667`
- average_recall: `0.0375`
- average_f1_score: `0.0611`
- average_latency_seconds: `0.0`

## Per-case metrics

| id | name | precision | recall | f1 | latency_s |
| --- | --- | ---: | ---: | ---: | ---: |
| wk1_case_001 | Phishing Email with SPF/DMARC Failure | 0.0 | 0.0 | 0.0 | 0.0 |
| wk1_case_002 | Phishing Variant with Lookalike Branding | 0.0 | 0.0 | 0.0 | 0.0 |
| wk1_case_003 | Benign Newsletter Control Sample | 1.0 | 0.25 | 0.4 | 0.0 |
| wk1_case_004 | Suspicious Newly Registered Domains | 0.0 | 0.0 | 0.0 | 0.0 |
| wk1_case_005 | Credential Leak Mention and ATO Risk | 0.0 | 0.0 | 0.0 | 0.0 |
| wk1_case_006 | Burst of Failed Logins from Automation Clients | 0.0 | 0.0 | 0.0 | 0.0 |
| wk1_case_007 | MFA Friction Followed by Single Success | 1.0 | 0.2 | 0.3333 | 0.0 |
| wk1_case_008 | NFC Relay Suspicion Across Multiple Cities | 0.0 | 0.0 | 0.0 | 0.0 |
| wk1_case_009 | Elevated POS NFC Duration Pattern | 0.0 | 0.0 | 0.0 | 0.0 |
| wk1_case_010 | Device Location Contradiction with Customer Statement | 0.0 | 0.0 | 0.0 | 0.0 |
| wk1_case_011 | Airport Check-In Correlated with Fraud Window | 0.0 | 0.0 | 0.0 | 0.0 |
| wk1_case_012 | Mixed Benign and Suspicious NFC Activity | 0.0 | 0.0 | 0.0 | 0.0 |
