# ReAct Improvement Worklog (Person 2)

This file summarizes all major work completed in this session, with exact edit locations, reasons, and impact.

## 1) Scope and goal

Goal: improve ReAct reliability without rebuilding the system.

Primary target (from `docs/team-onboarding/person-2-react-owner.md`):

- P0: schema consistency, deterministic stop reasons, core ReAct tests in CI.
- Start of P1 groundwork: safer runtime control behavior.

Non-goal:

- No architecture rewrite.
- No breaking API contract for existing frontend trace rendering.

## 2) Summary of completed changes

Completed:

1. Added shared runtime helpers for stop-reason normalization/resolution and trace construction.
2. Refactored G1 service to use shared helpers and deterministic precedence rules.
3. Refactored G2 service to align with the same runtime policy.
4. Strengthened unit tests for G1/G2 trace integrity and helper determinism.
5. Re-enabled core ReAct tests in `make test-ci`.

## 3) Detailed file-by-file log

## A. New shared runtime helper

File: `services/api/react_runtime.py`

Edited positions:

- `services/api/react_runtime.py:9` `STOP_REASON_PRIORITY`
- `services/api/react_runtime.py:18` `normalize_stop_reason(...)`
- `services/api/react_runtime.py:26` `resolve_stop_reason(...)`
- `services/api/react_runtime.py:39` `build_step_trace(...)`

Why:

- G1 and G2 previously had duplicated logic and could diverge.
- Needed one canonical way to resolve competing stop reasons.
- Needed one canonical StepTrace builder with required fields always filled.

## B. G1 runtime/service alignment

File: `services/api/g1_service.py`

Edited positions:

- `services/api/g1_service.py:28` imports shared runtime helpers.
- `services/api/g1_service.py:99` adds `_trace_step(...)` wrapper.
- `services/api/g1_service.py:152` normalize stop reason right after loop.
- `services/api/g1_service.py:158`, `:161`, `:165` resolve precedence for critic/action/policy gates.
- `services/api/g1_service.py:174` add `StructuredOutput` trace step in non-stream path.
- `services/api/g1_service.py:177` add `CriticReview` trace step in non-stream path.
- `services/api/g1_service.py:245` add `StructuredOutput` trace step in stream path.
- `services/api/g1_service.py:248` add `CriticReview` trace step in stream path.

Why:

- Keep stream and non-stream trace semantics consistent.
- Ensure stronger stop reasons are not accidentally overwritten later.
- Make trace steps easier to reason about in UI and metrics.

## C. G2 runtime/service alignment

File: `services/api/g2_service.py`

Edited positions:

- `services/api/g2_service.py:20` imports shared runtime helpers.
- `services/api/g2_service.py:43` adds `_trace_step(...)` wrapper.
- `services/api/g2_service.py:92` normalize stop reason from runner output.
- `services/api/g2_service.py:98`, `:102` resolve precedence after gates.
- `services/api/g2_service.py:147` normalize stop reason in stream path.
- `services/api/g2_service.py:153`, `:157` resolve precedence in stream path.

Why:

- G2 should follow the same deterministic policy as G1.
- Prevent inconsistent behavior between returned results and emitted steps.

## D. Unit test hardening

File: `tests/unit/test_service_g1_phase2.py`

Edited positions:

- `tests/unit/test_service_g1_phase2.py:3` import fixed to `services.api.g1_service`.
- `tests/unit/test_service_g1_phase2.py:44` adds trace-contract assertions.
- `tests/unit/test_service_g1_phase2.py:88` adds progress-path test for `StructuredOutput` and `CriticReview`.

Why:

- Old patch target path could miss actual runtime behavior.
- Needed explicit coverage for new stream/non-stream parity.

File: `tests/unit/test_multiagent.py`

Edited positions:

- `tests/unit/test_multiagent.py:82` adds required trace-field assertions.
- `tests/unit/test_multiagent.py:93` monkeypatch target fixed to `src.agents.g2.runner.Settings.MAX_AGENT_STEPS`.

Why:

- Ensure budget test patches the real setting used at runtime.
- Guard G2 step schema integrity.

File: `tests/unit/test_react_runtime.py` (new)

Edited positions:

- `tests/unit/test_react_runtime.py:10` tests normalize default behavior.
- `tests/unit/test_react_runtime.py:15` tests stop-reason priority ordering.
- `tests/unit/test_react_runtime.py:21` tests required StepTrace field population.

Why:

- Shared helper logic must be isolated and directly testable.

## E. CI gate adjustment

File: `Makefile`

Edited positions:

- `Makefile:18` `test-ci` target.
- `Makefile:19` comment marking Week-8/9 stabilization intent.
- `Makefile:20` now only ignores `test_rag_tools.py` and `integration/test_agent_flow.py`.

Why:

- Core ReAct tests should run in CI to catch regressions early.
- Keep a staged rollout by still excluding known unstable non-ReAct groups.

## 4) What has NOT been implemented yet

Not completed in code (important):

1. Full budget controller with explicit `max_tool_calls` tracking and enforcement in runtime service path.
2. Tool-call deduplication policy and optimization metrics.
3. Full frontend trace contract hardening and versioned schema docs.

Current status:

- Step budget and runtime budget already exist.
- Tool budget control is still pending and should be next P1 implementation.

## 5) Risk and rollback

Risks:

1. Minor UI expectation mismatch if trace stage ordering assumptions are too strict.
2. CI may fail if environment/fixtures are inconsistent after more tests are re-enabled.
