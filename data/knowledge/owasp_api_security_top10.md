# OWASP API Security Top 10 Quick Guide

## Key Risks

- API1 BOLA: enforce per-object authorization.
- API2 Broken Authentication: use strong token/session controls.
- API3 Broken Object Property Level Authorization: use response/request field allowlists.
- API4 Unrestricted Resource Consumption: rate limit and cap payload/timeouts.
- API5 Broken Function Level Authorization: protect admin/privileged routes.
- API6 Unrestricted Access to Sensitive Business Flows: add anti-automation controls.
- API7 SSRF: URL validation + egress controls.
- API8 Security Misconfiguration: hardened defaults in gateway and apps.
- API9 Improper Inventory Management: maintain API inventory and deprecations.
- API10 Unsafe Consumption of APIs: validate upstream data.

## Source/Reference

- OWASP API Security Top 10
