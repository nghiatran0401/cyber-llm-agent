# Frozen Contracts

> Frozen API baseline. Any breaking change requires: (1) update this document first, (2) maintainer approval, (3) PR description references the contract change. Non-breaking additions (new optional fields) can proceed with a note in the PR.

## 1. HTTP API Envelope

All endpoints return `ApiResponse`. Source: `services/api/schemas.py`.

### ApiResponse

| Field    | Type              | Required | Description                          |
| -------- | ----------------- | -------- | ------------------------------------ |
| `ok`     | `bool`            | Yes      | `true` on success, `false` on error  |
| `result` | `Any`             | No       | Response payload (`null` on error)   |
| `trace`  | `List[StepTrace]` | No       | Execution trace steps (default `[]`) |
| `meta`   | `ResponseMeta`    | Yes      | Request metadata                     |
| `error`  | `ErrorInfo`       | No       | Error details if `ok=false`          |

### ResponseMeta

| Field               | Type                   | Required | Description                 |
| ------------------- | ---------------------- | -------- | --------------------------- |
| `request_id`        | `str`                  | Yes      | UUID for this request       |
| `timestamp`         | `str`                  | Yes      | ISO-8601 UTC                |
| `api_version`       | `"v1"`                 | Yes      | Always `"v1"`               |
| `mode`              | `"g1" \| "g2" \| null` | No       | Agent mode used             |
| `model`             | `str \| null`          | No       | LLM model name              |
| `duration_ms`       | `int \| null`          | No       | Wall-clock time             |
| `stop_reason`       | `str \| null`          | No       | See stop_reason enum below  |
| `steps_used`        | `int \| null`          | No       | Agent loop iterations       |
| `prompt_version`    | `str \| null`          | No       | Template identifier         |
| `rubric_score`      | `float \| null`        | No       | Quality score 0.0-5.0       |
| `rubric_label`      | `str \| null`          | No       | See rubric_label enum below |
| `run_id`            | `str \| null`          | No       | Correlates with trace steps |
| `input_tokens_est`  | `int \| null`          | No       | Estimated input tokens      |
| `output_tokens_est` | `int \| null`          | No       | Estimated output tokens     |
| `total_tokens_est`  | `int \| null`          | No       | Estimated total tokens      |
| `cost_est_usd`      | `float \| null`        | No       | Estimated cost in USD       |
| `tool_calls`        | `int \| null`          | No       | Total tool invocations      |
| `tool_success`      | `int \| null`          | No       | Successful tool calls       |
| `tool_fail`         | `int \| null`          | No       | Failed tool calls           |

### ErrorInfo

| Field     | Type                     | Required | Description                                          |
| --------- | ------------------------ | -------- | ---------------------------------------------------- |
| `code`    | `str`                    | Yes      | Error code (e.g. `HTTP_401`, `HTTP_429`, `HTTP_500`) |
| `message` | `str`                    | Yes      | Human-readable error message                         |
| `details` | `Dict[str, Any] \| null` | No       | Additional context                                   |

### StepTrace

| Field            | Type          | Required | Description                           |
| ---------------- | ------------- | -------- | ------------------------------------- |
| `step`           | `str`         | Yes      | Step name (e.g. `"InputPreparation"`) |
| `what_it_does`   | `str`         | Yes      | Description                           |
| `prompt_preview` | `str`         | Yes      | Truncated prompt excerpt              |
| `input_summary`  | `str`         | Yes      | Truncated input summary               |
| `output_summary` | `str`         | Yes      | Truncated output summary              |
| `run_id`         | `str \| null` | No       | Links to parent run                   |
| `step_id`        | `str \| null` | No       | Unique step identifier                |
| `tool_call_id`   | `str \| null` | No       | For tool invocations                  |

### Enums

**`stop_reason`**: `"completed"` | `"blocked"` | `"needs_human"` | `"budget_exceeded"` | `"error"`

**`rubric_label`**: `"strong"` | `"acceptable"` | `"weak"` | `"disabled"` | `"n/a"`

## 2. Request Schemas

### AnalyzeRequest (POST `/api/v1/analyze/g1`, POST `/api/v1/analyze/g2`)

| Field           | Type          | Required | Default | Constraints    |
| --------------- | ------------- | -------- | ------- | -------------- |
| `input`         | `str`         | Yes      | —       | 1-50,000 chars |
| `session_id`    | `str \| null` | No       | `null`  | —              |
| `include_trace` | `bool`        | No       | `true`  | —              |

### ChatRequest (POST `/api/v1/chat`)

| Field           | Type           | Required | Default | Constraints    |
| --------------- | -------------- | -------- | ------- | -------------- |
| `input`         | `str`          | Yes      | —       | 1-50,000 chars |
| `mode`          | `"g1" \| "g2"` | No       | `"g1"`  | —              |
| `session_id`    | `str \| null`  | No       | `null`  | —              |
| `include_trace` | `bool`         | No       | `true`  | —              |

### WorkspaceStreamRequest (POST `/api/v1/workspace/stream`)

| Field        | Type                  | Required | Default  | Constraints    |
| ------------ | --------------------- | -------- | -------- | -------------- |
| `task`       | `"chat" \| "analyze"` | No       | `"chat"` | —              |
| `mode`       | `"g1" \| "g2"`        | No       | `"g1"`   | —              |
| `input`      | `str`                 | Yes      | —        | 1-50,000 chars |
| `session_id` | `str \| null`         | No       | `null`   | —              |

### SandboxSimulateRequest (POST `/api/v1/sandbox/simulate`)

| Field                | Type                              | Required | Default       | Constraints |
| -------------------- | --------------------------------- | -------- | ------------- | ----------- |
| `scenario`           | `"sqli" \| "xss" \| "bruteforce"` | Yes      | —             | —           |
| `vulnerable_mode`    | `bool`                            | No       | `false`       | —           |
| `source_ip`          | `str`                             | No       | `"127.0.0.1"` | —           |
| `append_to_live_log` | `bool`                            | No       | `true`        | —           |

### SandboxAnalyzeRequest (POST `/api/v1/sandbox/analyze`)

| Field           | Type             | Required | Default | Constraints                              |
| --------------- | ---------------- | -------- | ------- | ---------------------------------------- |
| `event`         | `Dict[str, Any]` | Yes      | —       | Max 32 keys, max 10,000 chars serialized |
| `mode`          | `"g1" \| "g2"`   | No       | `"g1"`  | —                                        |
| `session_id`    | `str \| null`    | No       | `null`  | —                                        |
| `include_trace` | `bool`           | No       | `true`  | —                                        |

## 3. Endpoint Registry

| Method | Route                               | Request Schema           | Response      |
| ------ | ----------------------------------- | ------------------------ | ------------- |
| GET    | `/api/v1/health`                    | —                        | `ApiResponse` |
| GET    | `/api/v1/ready`                     | —                        | `ApiResponse` |
| GET    | `/api/v1/metrics`                   | —                        | `ApiResponse` |
| GET    | `/api/v1/metrics/dashboard`         | —                        | `ApiResponse` |
| GET    | `/api/v1/sandbox/live-log`          | —                        | `ApiResponse` |
| GET    | `/api/v1/detections/recent`         | query: `?endpoint=`      | `ApiResponse` |
| GET    | `/api/v1/knowledge/owasp-mitre-map` | —                        | `ApiResponse` |
| POST   | `/api/v1/analyze/g1`                | `AnalyzeRequest`         | `ApiResponse` |
| POST   | `/api/v1/analyze/g2`                | `AnalyzeRequest`         | `ApiResponse` |
| POST   | `/api/v1/chat`                      | `ChatRequest`            | `ApiResponse` |
| POST   | `/api/v1/workspace/stream`          | `WorkspaceStreamRequest` | SSE stream    |
| POST   | `/api/v1/sandbox/simulate`          | `SandboxSimulateRequest` | `ApiResponse` |
| GET    | `/api/v1/sandbox/scenarios`         | —                        | `ApiResponse` |
| POST   | `/api/v1/sandbox/analyze`           | `SandboxAnalyzeRequest`  | `ApiResponse` |

## 4. Internal Service Return Contracts

### G1 Service (`services/api/g1_service.py`)

```
run_g1_analysis(user_input: str, session_id: Optional[str] = None)
  -> Tuple[str, List[StepTrace], str, str, int, str, Optional[float], str]
```

Return tuple: `(response_text, trace, model_name, stop_reason, steps_used, prompt_version, rubric_score, rubric_label)`

### G2 Service (`services/api/g2_service.py`)

```
run_g2_analysis(log_input: str)
  -> Tuple[Dict[str, Any], List[StepTrace], str, str, int, str, Optional[float], str]
```

Return tuple: `(result_dict, trace, model_name, stop_reason, steps_used, prompt_version, rubric_score, rubric_label)`

The `result_dict` contains keys: `final_report`, `log_analysis`, `threat_prediction`, `incident_response`, optionally `cti_evidence`.

## 5. Tool Call Contract

All tools are `langchain_core.tools.Tool` instances with `str -> str` signatures.

| Tool          | Function                                          | Source                         |
| ------------- | ------------------------------------------------- | ------------------------------ |
| RAG Retriever | `retrieve_security_context(query: str) -> str`    | `src/tools/rag_tools.py`       |
| CTI Fetcher   | `fetch_cti_intelligence(threat_type: str) -> str` | `src/tools/cti_tool.py`        |
| Log Parser    | `parse_system_log(log_file_path: str) -> str`     | `src/tools/log_parser_tool.py` |

Input is always a single string. Output is always a single string. This is the LangChain tool contract and must not change.

## 6. Memory Interface Contract

### ConversationMemory (`src/utils/memory_manager.py`)

Public API:

| Method                       | Signature                                                                | Description                                   |
| ---------------------------- | ------------------------------------------------------------------------ | --------------------------------------------- |
| `add_turn`                   | `(role: str, content: str) -> None`                                      | Append user/assistant message, enforce limits |
| `load_state`                 | `(messages, running_summary, episodic_memories, semantic_facts) -> None` | Restore from persisted data                   |
| `get_state`                  | `() -> Dict[str, object]`                                                | Serializable state snapshot                   |
| `render_context`             | `(query: str = "") -> str`                                               | Context string for prompt prepending          |
| `add_episodic_memory`        | `(summary: str, tags: List[str]) -> None`                                | Store episode for long-term recall            |
| `add_semantic_fact`          | `(fact: str) -> None`                                                    | Store stable fact for grounding               |
| `update_long_term_from_turn` | `(user_text: str, assistant_text: str) -> None`                          | Auto-derive episodic + semantic from turn     |
| `retrieve_relevant_memories` | `(query: str, max_items: int = None) -> List[str]`                       | Top relevant entries by token overlap         |

State keys returned by `get_state()`: `memory_type`, `max_messages`, `max_summary_chars`, `max_episodic_items`, `max_semantic_facts`, `recall_top_k`, `running_summary`, `messages`, `episodic_memories`, `semantic_facts`.

### SessionManager (`src/utils/session_manager.py`)

| Method                   | Signature                                            | Description                                |
| ------------------------ | ---------------------------------------------------- | ------------------------------------------ |
| `__init__`               | `(session_dir: Optional[Path] = None)`               | Defaults to `Settings.SESSIONS_DIR`        |
| `save_session`           | `(session_id: str, payload: Dict[str, Any]) -> None` | Persist to disk, auto-prunes expired       |
| `load_session`           | `(session_id: str) -> Dict[str, Any]`                | Read saved payload (empty dict if missing) |
| `prune_expired_sessions` | `() -> None`                                         | Delete files past retention policy         |

Session file format: JSON with `session_id`, `updated_at` (ISO-8601), plus payload keys.
