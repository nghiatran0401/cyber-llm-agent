# Tool Contracts

> Frozen tool baseline. All tool functions must return a ToolResult envelope.

## ToolResult Envelope

Every tool function returns `json.dumps(ToolResult)`. This is the standardized shape:

```json
{
  "ok": true,
  "data": <tool-specific payload>,
  "error": null,
  "error_type": null,
  "meta": {
    "tool": "LogParser",
    "duration_ms": 42,
    "retries": 0,
    "entries_count": 5,
    "input_hash": "a1b2c3d4e5f6"
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `ok` | `bool` | `true` on success, `false` on error |
| `data` | `Any` | Tool-specific payload on success; `null` on error |
| `error` | `str \| null` | Human-readable error message; `null` on success |
| `error_type` | `str \| null` | Machine-readable error category |
| `meta.tool` | `str` | Tool name: `"LogParser"`, `"CTIFetch"`, `"OWASPSandbox"` |
| `meta.duration_ms` | `int` | Execution time in milliseconds |
| `meta.retries` | `int` | Number of retries used (0 for tools without retry) |
| `meta.entries_count` | `int \| null` | LogParser: parsed entries; CTI: pulse count |
| `meta.input_hash` | `str` | Truncated SHA256 of input for correlation |

**LangChain compatibility**: `Tool.func` returns `json.dumps(tool_result)`. The LangChain agent loop receives a parseable JSON string.

**Source**: `src/tools/_tool_envelope.py`

## LogParser Contract

**Function**: `parse_system_log(log_file_path: str) -> str`
**Source**: `src/tools/log_parser_tool.py`

**Success**: `data` is `list[dict]` of parsed log entries. Each entry has `_raw` (original line), `_line` (line number), and optional Grok-parsed fields.

**Error types**:

| error_type | Trigger |
|------------|---------|
| `file_not_found` | Log file does not exist |
| `path_traversal` | Path resolves outside `data/logs/` |
| `validation_error` | Unsupported file extension |
| `permission_denied` | OS permission denied |
| `encoding_error` | Non-UTF-8 file content |
| `unknown` | Any other exception |

## CTIFetch Contract

**Function**: `fetch_cti_intelligence(threat_type: str) -> str`
**Source**: `src/tools/cti_tool.py`

**Success**: `data` is a short multi-line report: `Source` (AlienVault OTX or CTI Fallback), `Query`, `Summary`, plus pulse lines or IOC fields (`Associated pulses`, etc.). Text is control-stripped and length-capped in `cti_tool.py`.

**Fallback**: When OTX is unavailable, returns `ok: true` with fallback report in `data` and `meta.retries` set to max. The fallback content is deterministic and usable by the agent.

**Error types**:

| error_type | Trigger |
|------------|---------|
| `empty_query` | Empty threat_type input |
| `invalid_ioc_format` | Malformed `ioc:` prefix |
| `timeout` | Request timeout (handled via fallback) |
| `rate_limited` | HTTP 429 (handled via fallback) |

## OWASPSandbox Contract

**Function**: `generate_event(scenario_key, vulnerable_mode, source_ip) -> dict`
**Source**: `src/sandbox/owasp_sandbox.py`

Note: The sandbox is not a LangChain Tool — it is called by API routes directly. It returns a plain dict, not a ToolResult envelope.

**Event fields**: `timestamp`, `scenario_id`, `source_ip`, `endpoint`, `payload_pattern`, `status_code`, `risk_hint`, `raw_event`, `mode`.

**Errors**: `ValueError` for unknown scenario. `OSError` from `append_event_to_live_log()` on I/O failure (logged and re-raised).

## Telemetry Fields

All tools emit structured log entries:

| Field | Type | Description |
|-------|------|-------------|
| `tool_name` | `str` | LogParser, CTIFetch |
| `duration_ms` | `int` | Execution time |
| `retries` | `int` | Retry count |
| `ok` | `bool` | Success or failure |
| `error_type` | `str` | Error category (if failed) |
| `entries_count` | `int` | Result count |

**Log levels**: `INFO` on success, `WARNING` on fallback/recoverable failure, `ERROR` on unrecoverable failure.
