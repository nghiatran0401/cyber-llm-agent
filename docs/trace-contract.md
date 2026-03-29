# ReAct Trace Contract

## Purpose

This note defines the practical ReAct trace contract used in the current project.

It documents the trace shape that backend services emit, tests validate, and the frontend trace UI renders.

## Canonical StepTrace shape

The current runtime uses the `StepTrace` schema from `services/api/schemas.py`.

Trace contract version:

- `trace_schema_version = react-trace-v1`

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

## Canonical execution sequences

These sequences are the current golden traces validated by unit tests.

### G1 canonical sequence

1. `InputPreparation`
2. `RoutingPolicy`
3. `PromptVersion`
4. `SafetyGuard`
5. `SingleAgentExecution`
6. `RunControl`
7. `StructuredOutput`
8. `CriticReview`
9. `PolicyGuard`
10. `RubricEvaluation`

### G2 canonical sequence

For the default successful workflow without verifier retry:

1. `LogAnalyzer`
2. `WorkerPlanner`
3. `ThreatPredictor`
4. one or more `WorkerTask` steps
5. `IncidentResponder`
6. `Verifier`
7. `Orchestrator`

These canonical sequences matter because they make the trace explainable to humans and predictable for tests and UI rendering.

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
4. the trace contract has a named schema version and golden sequence coverage
