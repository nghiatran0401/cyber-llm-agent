# Security Policy

## Supported Versions

This project is under active development. Security fixes are applied on the default branch.

## Reporting a Vulnerability

If you discover a security issue, please do **not** open a public issue first.

Please report privately with:

- A clear description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested mitigation (if available)

Use private contact channels for initial disclosure. If no private channel is available yet, open an issue titled `Security: Private Disclosure Request` without exploit details, and maintainers will follow up privately.

## Security Practices

- No secrets committed to source control
- `.env` remains local only
- Sandbox mode is disabled in production by default
- Input size and file-type validation are enabled in UI entry points
- CI runs tests on every push and pull request
