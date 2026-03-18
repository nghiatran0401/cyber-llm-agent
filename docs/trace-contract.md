# ReAct Trace Contract

## Purpose

This note defines the practical ReAct trace contract used in the current project.

It documents the trace shape that backend services emit, tests validate, and the frontend trace UI renders.

## Canonical StepTrace shape

The current runtime uses the `StepTrace` schema from `services/api/schemas.py`.

Required fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `step` | `str` | Stable step name used for backend/frontend coordination |
| `what_it_does` | `str` | Human-readable explanation of the step |
| `prompt_preview` | `str` | Safe preview of the prompt or control input |
| `input_summary` | `str` | Short summary of what the step received |
| `output_summary` | `str` | Short summary of what the step produced |

Optional fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `run_id` | `str \| None` | Identifier for the full execution run |
| `step_id` | `str \| None` | Identifier for the current step in the run |
| `tool_call_id` | `str \| None` | Correlation ID for tool-related steps |

## Canonical stop reasons

Valid stop reasons:

- `completed`
- `budget_exceeded`
- `blocked`
- `needs_human`
- `error`

Priority rule:

- If multiple stop reasons could apply, the stronger reason wins according to runtime priority.
- Runtime helpers normalize unknown values back to a valid stop reason.

## Current practical contract decision

The project does **not** currently use a lower-level trace format such as:

- `type`
- `content`
- `ts`

Instead, the practical production contract in this repository is the human-readable `StepTrace` model above.

## Main implementation anchors

- `services/api/schemas.py`
- `services/api/react_runtime.py`
- `services/api/g1_service.py`
- `services/api/g2_service.py`
- `services/api/main.py`
- `apps/web/lib/types.ts`
- `apps/web/components/TracePanel.tsx`

## Week 1 closure note

Week 1 is considered functionally complete when:

1. the trace shape is explicitly documented
2. stop reasons are normalized and deterministic
3. core runtime tests for trace and stop reasons pass in a real test environment
