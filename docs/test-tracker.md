# Test Status Tracker

> Last updated: Sprint 1, Week 1. Owners must update this when fixing or adding excluded tests.

## Summary

| Metric | Count |
|--------|-------|
| Total tests | 56 |
| CI passing | 50 |
| CI excluded (requires API key) | 6 |
| Previously excluded (now fixed) | 11 |

## Passing Tests (in CI)

### `tests/unit/test_api_endpoints.py` — Owner: Person 1 (Platform)

| Test | Status |
|------|--------|
| `test_health_endpoint_returns_standard_envelope` | PASS |
| `test_g1_endpoint_uses_service_layer` | PASS |
| `test_sandbox_scenarios_endpoint` | PASS |
| `test_sandbox_endpoint_returns_403_when_disabled` | PASS |
| `test_workspace_stream_emits_trace_and_final` | PASS |
| `test_metrics_endpoint_returns_aggregates` | PASS |
| `test_metrics_dashboard_endpoint_returns_summary` | PASS |
| `test_auth_middleware_rejects_missing_key` | PASS |
| `test_rate_limit_middleware_returns_429` | PASS |

### `tests/unit/test_memory.py` — Owner: Person 4 (Memory)

| Test | Status |
|------|--------|
| `test_buffer_memory_enforces_max_messages` | PASS |
| `test_summary_memory_rolls_over_into_summary` | PASS |
| `test_long_term_memory_recall_returns_relevant_items` | PASS |
| `test_session_manager_save_and_load` | PASS |
| `test_stateful_agent_persists_memory_to_disk` | PASS |
| `test_session_manager_prunes_expired_sessions` | PASS |

### `tests/unit/test_evaluator.py` — Owner: Person 1 (Platform)

| Test | Status |
|------|--------|
| `test_evaluate_response_computes_precision_recall_f1` | PASS |
| `test_measure_latency_supports_invoke_agent` | PASS |
| `test_run_benchmark_returns_aggregate_metrics` | PASS |
| `test_evaluate_rubric_returns_score_and_label` | PASS |

### `tests/unit/test_tools.py` — Owner: Person 5 (Tooling)

| Test | Status |
|------|--------|
| `test_log_parser_with_mock_file` | PASS |
| `test_log_parser_file_not_found` | PASS |
| `test_log_parser_no_security_entries` | PASS |
| `test_cti_fetch_otx_threat_type_success` | PASS |
| `test_cti_fetch_otx_ioc_success` | PASS |
| `test_cti_fetch_otx_timeout_fallback` | PASS |
| `test_cti_fetch_otx_http_429_fallback` | PASS |
| `test_cti_fetch_invalid_ioc_input` | PASS |
| `test_cti_fetch_output_sanitized_and_truncated` | PASS |
| `test_log_parser_rejects_absolute_path_outside_logs_dir` | PASS |

### `tests/unit/test_sandbox.py` — Owner: Person 5 (Tooling)

| Test | Status |
|------|--------|
| `test_list_scenarios_contains_three_core_cases` | PASS |
| `test_generate_event_has_required_fields` | PASS |
| `test_append_event_writes_jsonl` | PASS |
| `test_event_to_analysis_text_contains_risk_hint` | PASS |

### `tests/unit/test_state_validator.py` — Owner: Person 2 (ReAct)

| Test | Status |
|------|--------|
| `test_validate_state_accepts_complete_state` | PASS |
| `test_validate_state_raises_for_missing_keys` | PASS |

### `tests/unit/test_prompt_manager.py` — Owner: Person 2 (ReAct)

| Test | Status |
|------|--------|
| `test_list_prompt_versions_reads_prefix` | PASS |
| `test_run_ab_test_returns_best_variant` | PASS |

### `tests/test_benchmark_runner.py` — Owner: Person 1 (Platform)

| Test | Status |
|------|--------|
| `test_load_dataset_reads_test_cases` | PASS |
| `test_load_dataset_rejects_non_list_test_cases` | PASS |
| `test_normalize_cases_applies_limit_and_skips_empty_logs` | PASS |
| `test_write_artifacts_and_load_latest_report` | PASS |
| `test_offline_agent_and_evaluator_end_to_end` | PASS |
| `test_real_llm_agent_rejects_unsupported_provider` | PASS |

### `tests/test_scenarios.py` — Owner: Person 1 (Platform)

| Test | Status |
|------|--------|
| `test_benchmark_suite_runs_with_six_cases` | PASS |

---

## Previously Excluded Tests — Now Fixed and Restored to CI

### `tests/unit/test_multiagent.py` — Owner: Person 2 (ReAct)

**Was:** Excluded due to stale imports after G2 refactor.
**Fix applied:** Updated imports to use `src.agents.g2.state`, `src.agents.g2.nodes`, `src.agents.g2.graph`, `src.agents.g2.runner`.

| Test | Status |
|------|--------|
| `test_multiagent_nodes_update_state_sequentially` | RESTORED |
| `test_log_analyzer_rejects_empty_logs` | RESTORED |
| `test_create_multiagent_workflow_runs_end_to_end` | RESTORED |
| `test_run_multiagent_with_trace_returns_four_steps` | RESTORED |
| `test_run_multiagent_with_trace_stops_when_step_budget_exceeded` | RESTORED |

### `tests/unit/test_rag_tools.py` — Owner: Person 3 (RAG)

**Was:** Excluded because RAG moved to Pinecone; tests referenced old local index API.
**Fix applied:** Rewrote tests to mock `PineconeVectorStore` and `OpenAIEmbeddings`.

| Test | Status |
|------|--------|
| `test_rag_ingest_and_retrieve` | RESTORED |
| `test_rag_retrieve_empty_index` | RESTORED |
| `test_rag_citation_format` | RESTORED |

### `tests/unit/test_service_g1_phase2.py` — Owner: Person 2 (ReAct)

**Was:** Excluded because service layer refactored from `service.py` to `g1_service.py`.
**Fix applied:** Updated imports and monkeypatch targets to `services.api.g1_service`.

| Test | Status |
|------|--------|
| `test_g1_adds_structured_and_critic_trace` | RESTORED |
| `test_g1_high_risk_without_citations_requires_human` | RESTORED |
| `test_g1_prompt_injection_triggers_needs_human` | RESTORED |

---

## Excluded Tests — Requires OPENAI_API_KEY (manual pre-release)

### `tests/integration/test_agent_flow.py` — Owner: Person 2 (ReAct) + Person 5 (Tooling)

**Root cause:** Module-level `pytest.mark.skipif(not OPENAI_API_KEY)`. These are integration tests requiring real API calls.
**Policy:** Keep excluded from CI. Run manually once before each release.

| Test | Status | Owner |
|------|--------|-------|
| `test_base_agent_initialization` | MANUAL | Person 2 |
| `test_base_agent_analyze_log` | MANUAL | Person 2 |
| `test_base_agent_empty_log` | MANUAL | Person 2 |
| `test_simple_agent_creation` | MANUAL | Person 2 |
| `test_simple_agent_with_real_api` | MANUAL | Person 2 |
| `test_agent_tool_integration` | MANUAL | Person 5 |
| `test_agent_cti_fetch` | MANUAL | Person 5 |

> Note: `test_simple_agent_creation` uses mocks and could potentially run in CI. Person 2 to evaluate by Week 2.
