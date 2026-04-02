# Person 5 Onboarding - Tooling Owner (CTI + Log Parser + Lab)

## 1) Project Context (plain English)

Tools are how agents gather real evidence.

In this project, your core tools are:

- log parser
- CTI lookup
- sandbox/lab support for security scenarios

If tools are unstable, the entire agent system becomes unreliable.

## 2) Current Status (frank)

Current maturity for your track: **6.0/10**

What this means:

- Tooling is functional and useful.
- But outputs are not fully standardized yet.
- Reliability and error behavior need tightening.

Main reality today:

- Some tool outputs are still too string-oriented.
- Retry/error handling exists but can be clearer and more consistent.
- Lab and tool contracts must stay aligned with API and UI expectations.

## 3) What Is Already Implemented

- CTI tool with provider calls and fallback behavior.
- Log parser tool used by agent workflows.
- Sandbox generation and event simulation.
- Vulnerable lab app with dashboard routes and telemetry.
- Unit tests for tools and sandbox.

## 4) What Must Improve

- Standardize tool output envelope (`ok/data/error/meta` pattern).
- Improve typed error behavior and retry clarity.
- Strengthen telemetry and reliability visibility.
- Keep lab behavior aligned with backend contract changes.

## 5) Your 4-Week Plan

### Week 1

- Freeze tool contract and unhappy-path test matrix.
- Define telemetry fields for success/fail/retry/latency.

### Week 2

- Refactor CTI/parser outputs to strict contract.
- Improve timeout/retry/backoff and explicit error types.

### Week 3

- Integrate tooling outputs cleanly with ReAct trace interfaces.
- Validate sandbox/lab compatibility with API and UI.

### Week 4

- Reliability hardening and flaky-case cleanup.
- Publish tooling runbook and reliability report.

## 6) First Files To Read

- `src/tools/log_parser_tool.py`
- `src/tools/cti_tool.py`
- `src/sandbox/owasp_sandbox.py`
- `apps/vuln-lab/server.js`
- `apps/vuln-lab/src/routes/dashboardRoutes.js`
- `tests/unit/test_tools.py`
- `tests/unit/test_sandbox.py`

## 7) How You Know You Are Succeeding

- Tool outputs are predictable for all agent flows.
- Failures are clear and recoverable.
- CTI/parser regressions are caught by tests.
- Lab scenarios remain compatible with backend changes.
