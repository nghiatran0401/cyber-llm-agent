# Secure Coding Guidelines for Web Applications

## Input/Output Safety
- Validate untrusted input at boundaries.
- Encode output by context (HTML/JS/URL/CSS).

## AuthN/AuthZ
- Enforce server-side authorization checks on every request.
- Rotate tokens/sessions on login and privilege changes.

## Secrets and Data Protection
- Never hardcode secrets.
- Encrypt sensitive data in transit and at rest.

## Dependency Security
- Monitor CVEs and patch critical dependencies quickly.

## Logging
- Log security events; never log secrets/tokens.

## Source/Reference

- OWASP ASVS
- OWASP Proactive Controls
