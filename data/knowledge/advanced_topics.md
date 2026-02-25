# Advanced Cybersecurity Topics

## Scope

This document captures higher-complexity topics for deeper analysis, beyond baseline SOC triage and OWASP fundamentals.

## Advanced Web and API Security

- SSRF hardening in cloud-native environments
  - Block metadata endpoints and private address space by default
  - Apply strict outbound egress allowlists for server-side fetchers
- Insecure deserialization and parser exploitation
  - Prefer safe serialization formats and strict schema validation
  - Isolate high-risk parsing paths and monitor crash/error patterns
- Business logic abuse and anti-automation evasion
  - Model abuse workflows (coupon abuse, account takeover, scalping)
  - Add adaptive controls (risk scoring, step-up auth, velocity checks)
- API trust boundary failures in microservices
  - Enforce service identity and authorization on internal APIs
  - Validate downstream assumptions for all propagated identity claims

## Advanced Detection and Threat Hunting

- Multi-stage attack correlation
  - Link initial access, privilege escalation, persistence, and exfiltration signals
  - Build timeline with identity, endpoint, and network telemetry
- ATTACK technique chaining
  - Detect sequence patterns rather than isolated alerts
  - Prioritize detections on privileged paths and crown-jewel assets
- Detection quality engineering
  - Track precision/recall trends and tune for high-fidelity alerts
  - Measure detection latency and missed coverage by scenario

## Advanced Incident Response

- Enterprise containment under business constraints
  - Apply risk-based containment when full isolation impacts critical services
  - Use segmented containment and just-in-time access revocation
- Forensic rigor in large incidents
  - Preserve chain of custody across teams and tools
  - Standardize evidence naming, hashing, and retention controls
- Crisis communications and executive reporting
  - Translate technical impact into business impact with confidence levels
  - Maintain update cadence with clear decision requests

## Advanced Identity Security

- Session hijack and token replay mitigation
  - Short token lifetimes, audience restrictions, and rotation on risk events
- Privilege path analysis
  - Map escalation paths from standard accounts to admin/control plane
- Identity-aware detection
  - Correlate auth events with endpoint behavior and risky API operations

## Cloud and Supply Chain Security

- Misconfiguration drift detection
  - Continuously compare cloud configs to secure baselines
- CI/CD compromise risks
  - Protect build pipelines, artifact signing, and deployment credentials
- Third-party dependency trust
  - Monitor critical dependency health and exploit activity

## Suggested Use in RAG Answers

- Prefer this file when user asks for architecture-level tradeoffs, deep-dive response strategy, or advanced threat-hunting approaches.
- Pair with specific playbooks (OWASP, IR, IOC triage) for actionable next steps.

## Source/Reference

- OWASP Cheat Sheet Series and ASVS guidance
- MITRE ATT&CK Enterprise knowledge base
- NIST SP 800-61 incident handling guidance
- CISA defensive operations recommendations
