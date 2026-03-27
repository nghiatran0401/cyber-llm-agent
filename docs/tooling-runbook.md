# Tooling Runbook

Operational guide for debugging and maintaining the agent tool layer.

## Tool Inventory

| Tool | File | Input | Output | Error Handling |
|------|------|-------|--------|----------------|
| LogParser | `src/tools/log_parser_tool.py` | File path (str) | ToolResult JSON | 5 error types, no retry |
| CTIFetch | `src/tools/cti_tool.py` | Threat query (str) | ToolResult JSON | Retry + backoff + fallback |
| OWASPSandbox | `src/sandbox/owasp_sandbox.py` | Scenario key (str) | Plain dict | ValueError + OSError |

## Common Failure Modes

### LogParser

| Symptom | Cause | Fix |
|---------|-------|-----|
| `error_type: file_not_found` | Log file doesn't exist | Check `LOGS_DIR` setting, verify file path |
| `error_type: permission_denied` | OS file permissions | `chmod 644` on log file, check process user |
| `error_type: path_traversal` | Path resolves outside `data/logs/` | Use relative paths within `data/logs/` |
| `error_type: encoding_error` | Non-UTF-8 file | Convert file: `iconv -f latin1 -t utf-8 file.log > file_utf8.log` |
| `error_type: validation_error` | Wrong file extension | Use allowed extensions: `.log`, `.txt`, `.json`, `.jsonl` |

### CTIFetch

| Symptom | Cause | Fix |
|---------|-------|-----|
| Fallback report returned | OTX API timeout/error | Check OTX API status, verify `OTX_API_KEY` |
| `error_type: empty_query` | Empty input to tool | Agent bug — check prompt template |
| `error_type: invalid_ioc_format` | Wrong IOC syntax | Format: `ioc:<type>:<value>` where type ∈ {ip, domain, hostname, url, hash} |
| `meta.retries > 0` in success | Transient OTX errors | Monitor; increase `CTI_MAX_RETRIES` if frequent |
| All requests returning fallback | API key invalid/expired | Rotate `OTX_API_KEY` in `.env` |

### OWASPSandbox

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ValueError: Unknown scenario` | Invalid scenario key | Use `list_scenarios()` — valid: sqli, xss, bruteforce |
| `OSError` on log append | Disk full or permission denied | Check disk space, verify `LOGS_DIR` permissions |

## Debugging Guide

### Reading ToolResult Envelopes

All tool outputs are JSON strings with this shape:
```json
{"ok": true/false, "data": ..., "error": ..., "error_type": ..., "meta": {...}}
```

1. Parse the JSON: `json.loads(tool_output)`
2. Check `ok` — `false` means the tool failed
3. Check `error_type` for the failure category
4. Check `meta.duration_ms` for latency
5. Check `meta.retries` — values > 0 indicate transient issues
6. Use `meta.input_hash` to correlate across log entries

### Correlating Tool Calls

1. Find the request in API logs by `run_id`
2. Check trace steps for `tool_call_id`
3. Search tool logs for matching `input_hash`

## Configuration Reference

| Setting | Default | Used By |
|---------|---------|---------|
| `LOGS_DIR` | `data/logs` | LogParser |
| `ALLOWED_LOG_EXTENSIONS` | `.log,.txt,.json,.jsonl` | LogParser |
| `CTI_PROVIDER` | `otx` | CTIFetch |
| `OTX_API_KEY` | (required) | CTIFetch |
| `OTX_BASE_URL` | `https://otx.alienvault.com/api/v1` | CTIFetch |
| `CTI_REQUEST_TIMEOUT_SECONDS` | `10` | CTIFetch |
| `CTI_MAX_RETRIES` | `2` | CTIFetch |
| `CTI_RETRY_BACKOFF_SECONDS` | `0.5` | CTIFetch |
| `CTI_MAX_RESPONSE_CHARS` | `3000` | CTIFetch |
| `CTI_TOP_RESULTS` | `5` | CTIFetch |
| `ENABLE_SANDBOX` | `false` | OWASPSandbox |

## Adding a New Tool

1. Implement the function in `src/tools/`
2. Import `build_tool_result`, `serialize_tool_result` from `_tool_envelope.py`
3. Wrap all return paths in `serialize_tool_result(build_tool_result(...))`
4. Create a `langchain_core.tools.Tool` object
5. Add the tool to the agent's tool list in `src/agents/g1/adaptive_agent.py`
6. Document in `docs/tool-contracts.md`
7. Add happy-path + unhappy-path tests to `tests/unit/test_tools.py`
