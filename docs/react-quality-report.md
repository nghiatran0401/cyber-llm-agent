# ReAct Quality Report

## Purpose

This document records the current quality signals used to evaluate the ReAct runtime.

It is meant to support Week 4 reporting for:

- completion quality
- over-calling behavior
- stop-reason quality
- reproducible reporting

## 1) Quality questions

The ReAct runtime should answer these questions clearly:

1. Does the run complete successfully?
2. If it does not complete, does it stop for a deterministic reason?
3. Does it avoid redundant tool calls?
4. Does it stay within declared step, time, and tool budgets?
5. Are trace outputs rich enough to explain what happened?

## 2) Runtime metrics currently exposed

The API exposes runtime metrics through:

- `/api/v1/metrics`
- `/api/v1/metrics/dashboard`
- `/api/v1/detections/recent`

### Core metrics

- `requests_total`
- `success_total`
- `error_total`
- `avg_duration_ms`
- `tool_calls_total`
- `tool_fail_total`
- `duplicate_tool_calls_total`
- `semantic_duplicate_tool_calls_total`
- `cached_tool_reuses_total`
- `cooldown_skips_total`
- `by_stop_reason`

### Dashboard summary metrics

- `success_rate_pct`
- `avg_tokens_est`
- `avg_tool_calls_per_run`
- `avg_duplicate_tool_calls_per_run`
- `tool_fail_rate_pct`
- `budget_exceeded_rate_pct`
- `needs_human_rate_pct`

These metrics are useful because they convert ReAct quality into observable counters rather than anecdotal claims.

## 3) Interpretation guide

### Good signals

- Lower `avg_tool_calls_per_run` without reducing completion quality
- Lower `avg_duplicate_tool_calls_per_run`
- Higher `cached_tool_reuses_total` when the same run asks for semantically equivalent evidence
- Higher `cooldown_skips_total` only after real tool failures, not during normal runs
- Stable `tool_fail_rate_pct`
- Low unexpected `error` stop reasons
- Trace steps remain readable and consistent

### Warning signals

- Rising `budget_exceeded_rate_pct`
- Rising `needs_human_rate_pct` without corresponding safety requirements
- High `tool_fail_rate_pct`
- Many unknown or inconsistent trace steps

## 4) Reproducible validation workflow

### Core runtime tests

Run:

```powershell
py -m pytest -q tests/unit/test_react_runtime.py tests/unit/test_g1_service.py tests/unit/test_multiagent.py tests/unit/test_api_endpoints.py tests/unit/test_guardrails.py
```

These tests cover:

- stop-reason normalization
- loop budget behavior
- exact duplicate reuse
- semantic duplicate reuse
- failure cooldown after tool errors
- streamed trace metadata
- guardrail edge cases

### Golden trace tests

The test suite also validates canonical trace sequences for:

- G1 end-to-end analysis
- G2 default successful workflow

These tests matter because they prove the trace is predictable, not just present.

### Benchmark workflow

Offline benchmark:

```powershell
make benchmark
```

Latest benchmark report:

```powershell
make benchmark-report
```

Reference benchmark guidance:

- `docs/benchmark-evaluation.md`

## 5) Current practical conclusion

At the current state of the project:

- Week 1 established the trace and stop-reason foundation.
- Week 2 established bounded execution and duplicate-call control.
- Week 3 improves readability and contract consistency across backend and frontend.
- Week 4 improves hardening and reporting so the runtime can be evaluated with reproducible signals.

The current runtime now goes beyond exact-match dedupe by reusing cached tool results for semantically equivalent intent keys and by cooling down failed tool intents inside the same run.
