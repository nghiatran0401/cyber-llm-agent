# Web Security Testing Checklist

## Authentication and Session
- Test lockout, MFA bypass, session rotation, and logout invalidation.

## Authorization
- Test horizontal and vertical privilege escalation.
- Validate object-level checks on all sensitive endpoints.

## Injection and Input Handling
- Test SQL/NoSQL injection, command injection, and template injection.

## XSS and Client-Side
- Test reflected/stored/DOM XSS.
- Verify output encoding and CSP effectiveness.

## API and Business Logic Abuse
- Test BOLA/BFLA, replay abuse, and weak rate limiting.

## File Handling
- Test unsafe upload/download and path traversal controls.

## Source/Reference

- OWASP WSTG
- OWASP ASVS
