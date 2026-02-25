# OWASP Top 10 Web Security Playbook

## A01 Broken Access Control
- Enforce server-side authorization checks on every sensitive action.

## A02 Cryptographic Failures
- Use TLS everywhere and strong key management.

## A03 Injection
- Use parameterized queries and input validation.

## A04 Insecure Design
- Add threat modeling and abuse-case reviews for critical features.

## A05 Security Misconfiguration
- Disable debug defaults and harden headers/CORS.

## A06 Vulnerable and Outdated Components
- Patch high/critical CVEs and maintain upgrade cadence.

## A07 Identification and Authentication Failures
- Harden session lifecycle and require MFA where needed.

## A08 Software and Data Integrity Failures
- Verify artifact integrity and lock down CI/CD trust boundaries.

## A09 Security Logging and Monitoring Failures
- Log security events and create alerting runbooks.

## A10 SSRF
- Restrict outbound requests with strict allowlists and egress filters.

## Source/Reference

- OWASP Top 10 (2021)
- OWASP ASVS
