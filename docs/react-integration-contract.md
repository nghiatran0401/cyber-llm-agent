# ReAct Integration Contract

## Purpose

This document defines the integration-facing contract for the agent-loop runtime (ReAct-style tool execution) in this repository.

It focuses on how the runtime interacts with:

- tool outputs
- memory and retrieval context
- trace rendering
- retry and abort semantics

## 1) Tool output contract

The runtime assumes that tool integrations return plain text, but it now normalizes several important edge cases.

### Supported tool outcomes

1. Successful output
- Non-empty text is treated as usable tool evidence.

2. Empty output
- Empty or whitespace-only output is normalized to:
  - ``<ToolName> returned no usable output for this request.``
- This is counted as a tool failure for runtime reporting.

3. Tool execution failure
- Exceptions raised by tool execution are normalized to:
  - ``<ToolName> is temporarily unavailable because tool execution failed.``
- This is counted as a tool failure for runtime reporting.

4. Exact duplicate reuse
- If the same tool receives the same normalized input in the same run, the runtime reuses the cached result instead of executing the tool again.

5. Semantic duplicate reuse
- If the same tool receives a semantically equivalent request in the same run, the runtime reuses the cached result for the matching intent key.
- Example:
  - `possible ransomware activity`
  - `ransomware attack`
  - `ransomware`
  may all reuse the same `CTIFetch` result in one run.

6. Failure cooldown
- If a tool fails for one intent key, semantically equivalent retries in the same run are skipped with a deterministic cooldown message.

### Why this contract exists

Without a stable tool-output contract, downstream trace and metrics become difficult to interpret.

The runtime therefore guarantees that tool-related edge cases degrade to deterministic text instead of failing silently.

It also guarantees that redundant calls are handled through:

- exact duplicate reuse
- semantic-intent reuse
- failure cooldown

## 2) Memory, retrieval, and CTI expectations

### Memory

- Memory-backed G1 execution should still emit the same `StepTrace` contract as non-memory paths.
- Memory changes should not alter the shape of `RunControl`, `StructuredOutput`, `CriticReview`, or `PolicyGuard`.

### Retrieval (RAG)

- Retrieval output is treated as contextual evidence, not as a separate trace schema.
- If retrieval is disabled, the runtime should still emit readable trace and control summaries.
- Retrieval misses should remain deterministic and non-crashing.
- Retrieval results that are already usable in the current run should be reused instead of fetched again.

### CTI

- Live CTI failures already degrade to a deterministic fallback report.
- Agent-loop runtime metrics should treat CTI fallback or unavailable output as evidence of degraded tool quality, not as a silent success.
- CTI queries for the same threat family should reuse prior in-run evidence whenever the runtime can map them to one intent key.

## 3) Trace rendering contract

Backend and frontend must agree on the following `StepTrace` fields:

- `step`
- `what_it_does`
- `prompt_preview`
- `input_summary`
- `output_summary`

Optional trace metadata:

- `run_id`
- `step_id`
- `tool_call_id`

### Rendering rules

- `RunControl`, `PolicyGuard`, and `RubricEvaluation` may be rendered as structured summary cards instead of raw text.
- Other steps should still preserve their raw prompt/input/output summaries for debugging and teaching.
- Trace metadata should be visible but visually secondary to the human-readable step meaning.
- `RunControl` should include trace-schema and budget-efficiency counters so UI and backend agree on the meaning of runtime state.

## 4) Retry and abort semantics

The runtime follows these practical rules:

1. Retry only when a specific workflow step explicitly supports it.
- Example: G2 verifier-triggered responder retry.

2. Abort when runtime budget is exceeded.
- Stop reason: `budget_exceeded`

3. Escalate to human review when safety or evidence gates fail.
- Stop reason: `needs_human`

4. Mark as blocked when the workflow cannot progress to a valid final answer.
- Stop reason: `blocked`

5. Preserve the strongest stop reason when multiple gates fire.
- This is handled by the shared stop-reason priority rules.

## 5) Current implementation anchors

- `services/api/agent_loop_runtime.py`
- `services/api/g1_service.py`
- `services/api/g2_service.py`
- `services/api/main.py`
- `src/agents/g1/adaptive_agent.py`
- `src/agents/g2/nodes.py`
- `src/agents/g2/runner.py`
- `apps/web/components/TracePanel.tsx`
