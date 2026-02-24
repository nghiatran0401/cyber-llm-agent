# Contributing Guide

Thanks for your interest in improving this project.

## Development Setup

1. Clone the repository
2. Create and activate a Python 3.10+ environment
3. Install dependencies:

```bash
make install
```

4. Configure environment:

```bash
cp .env.example .env
# then add OPENAI_API_KEY
```

## Local Quality Checks

Run these before opening a pull request:

```bash
make lint
make test
make smoke
```

## Pull Request Standards

- Keep changes scoped and atomic
- Add tests for behavior changes
- Update docs when APIs or usage change
- Avoid introducing breaking changes without migration notes

## Commit Messages

Use concise, imperative messages, for example:

- `Add request timeout guard for CTI fetch`
- `Refine Streamlit error state for empty logs`
