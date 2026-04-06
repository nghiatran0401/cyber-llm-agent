# PR Merge Checklist

Every pull request must satisfy all of the following before merge.

## Required Checks

- [ ] **CI green** — All steps in `.github/workflows/ci.yml` pass (lint, test-ci, benchmark, memory tests, frontend tests).
- [ ] **No contract breaks without approval** — If the PR modifies `services/api/schemas.py`, any service return tuple, tool function signatures, or `ConversationMemory`/`SessionManager` public methods, it must reference `docs/contracts.md` and have explicit maintainer approval.
- [ ] **Tests exist for behavior changes** — New or changed behavior has a corresponding test in `tests/`. If the test requires real external keys/services, keep it out of `scripts/run_test_ci.py` and document how/when it is run in the PR description.
- [ ] **No CI scope reduction without rationale** — If `scripts/run_test_ci.py` is changed to remove or weaken core workflow coverage, explain owner, reason, and follow-up in the PR description.
- [ ] **Docs updated** — If the PR changes an API endpoint, tool, or memory interface, update `docs/contracts.md`.
- [ ] **Scoped changes** — PR touches one concern. Multi-concern PRs require justification.
- [ ] **Lint clean** — `make lint` passes locally before push.
- [ ] **Review** — At least one team member (not the author) approves.

## PR Description Template

```markdown
## What
[One sentence describing the change]

## Why
[One sentence explaining the motivation]

## Contracts affected
- [ ] None
- [ ] schemas.py
- [ ] Service return types
- [ ] Tool signatures
- [ ] Memory interface

## Tests
- [ ] Existing tests cover this
- [ ] New tests added
- [ ] CI test scope changed (`scripts/run_test_ci.py` + PR rationale)
```
