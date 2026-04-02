# Policy Gates and Return Behavior

This document lists the active policy/safety gates and what each one returns.

Only the gates below are kept.

## Active gates

### 1) Input Validation
- **Where:** `services/api/guardrails.py` (`validate_input`, `validate_event_payload`), called from `g1_service` / `g2_service` / `sandbox_service`
- **Checks:**
  - non-empty input
  - max request size (`MAX_INPUT_CHARS`)
  - sandbox event shape/size limits
- **Return behavior:**
  - raises `ValueError`
  - API returns `HTTP 400` with standard error envelope

### 2) Output Policy Guard
- **Where:** `services/api/guardrails.py` (`apply_output_policy_guard`), invoked from `g1_service` / `g2_service`
- **Checks:**
  - denylist markers in generated output
- **Return behavior:**
  - replaces output with safe blocked message
  - `stop_reason=needs_human`

### 3) High-Risk Evidence / Human Gating
- **Where:** `services/api/guardrails.py` (`apply_action_gating`), invoked from `g1_service` / `g2_service`
- **Checks:**
  - if high-risk task, requires minimum evidence markers
  - optional explicit human approval gate
- **Return behavior:**
  - insufficient evidence or approval required:
    - appends safety note
    - `stop_reason=needs_human`
  - otherwise:
    - `stop_reason=completed`

### 4) Runtime Budget Limits
- **Where:**
  - `services/api/g1_service.py` (`_run_single_agent_loop`)
  - `src/agents/g2/runner.py` (`run_multiagent_with_trace`)
- **Checks:**
  - max steps
  - max runtime seconds
- **Return behavior:**
  - budget hit: `stop_reason=budget_exceeded`
  - otherwise normal completion path

## Strongly Recommended

### 5) Prompt-Injection Gate
- **Always on** — there is no environment variable to disable it.
- **Where:** `services/api/guardrails.py` (`detect_prompt_injection`), used from `g1_service` / `g2_service`
- **Checks:**
  - heuristic marker match on input text
- **Return behavior:**
  - short-circuits run
  - safe warning message returned
  - `stop_reason=needs_human`

### 6) Critic Gate (Quality Consistency)
- **Where:** `services/api/response_parser.py` (`critic_validate_structured_output`), used from `g1_service`
- **Checks:**
  - structured output consistency
  - required fields/evidence for high-risk responses
- **Return behavior:**
  - appends critic verdict requesting more evidence/context
  - `stop_reason=needs_human`

## Notes

- Rubric scoring is still available as an evaluation signal; it is not a blocking gate.
- Response metadata is returned via `meta` fields on API responses (`run_id`, `stop_reason`, `steps_used`, token/cost estimates, etc.).
