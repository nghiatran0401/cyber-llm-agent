# Security Knowledge Base (Starter)

This is a local knowledge seed file for basic retrieval-augmented generation (RAG) tests.

## Brute Force Indicators

- Many failed login attempts in a short window
- Repeated attempts against one account from multiple IPs
- Repeated attempts from one IP against many accounts

Recommended immediate actions:

- Temporarily block source IP addresses with repeated failures
- Enforce MFA for exposed users
- Reset potentially compromised credentials
- Check authentication logs for lateral movement indicators

## SQL Injection Indicators

- Payload patterns like `' OR '1'='1` or `UNION SELECT`
- Database error text reflected to users
- Unexpected spikes in failed application queries

Recommended immediate actions:

- Apply strict input validation and parameterized queries
- Block suspicious request signatures at WAF
- Review application and database logs for suspicious query patterns

## XSS Indicators

- Script tags or JavaScript handlers in untrusted input
- Unexpected browser-side alerts or redirects
- Reflected payload fragments in rendered pages

Recommended immediate actions:

- Apply output encoding by context
- Add/strengthen Content Security Policy
- Sanitize user-supplied HTML/JS-bearing fields
