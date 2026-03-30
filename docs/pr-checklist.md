# PR Merge Checklist

Every pull request must satisfy all of the following before merge.

## Required Checks

- [ ] **CI green** — All steps in `.github/workflows/ci.yml` pass (lint, test-ci, benchmark, smoke, frontend tests).
- [ ] **No contract breaks without approval** — If the PR modifies `services/api/schemas.py`, any service return tuple, tool function signatures, or `ConversationMemory`/`SessionManager` public methods, it must reference `docs/contracts.md` and have Person 1 (Platform Lead) approval.
- [ ] **Tests exist for behavior changes** — New or changed behavior has a corresponding test in `tests/`. If the test cannot run in CI (e.g., requires `OPENAI_API_KEY`), add it to `tests/integration/` and document in `docs/test-tracker.md`.
- [ ] **No new test exclusions without tracker entry** — If a test is added to the `--ignore` list in `Makefile:test-ci`, it must be logged in `docs/test-tracker.md` with owner and fix date.
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
- [ ] Test exclusion added (tracker updated)
```
