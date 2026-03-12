# T1199 - Trusted Relationship

**Tactic:** Initial Access
**Platforms:** IaaS, Identity Provider, Linux, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1199

## Description

Adversaries may breach or otherwise leverage organizations who have access to intended victims. Access through trusted third party relationship abuses an existing connection that may not be protected or receives less scrutiny than standard mechanisms of gaining access to a network.

Organizations often grant elevated access to second or third-party external providers in order to allow them to manage internal systems as well as cloud-based environments. Some examples of these relationships include IT services contractors, managed security providers, infrastructure contractors (e.g. HVAC, elevators, physical security). The third-party provider's access may be intended to be limited to the infrastructure being maintained, but may exist on the same network as the rest of the enterprise. As such, Valid Accounts used by the other party for access to internal network systems may be compromised and used.

In Office 365 environments, organizations may grant Microsoft partners or resellers delegated administrator permissions. By compromising a partner or reseller account, an adversary may be able to leverage existing delegated administrator relationships or send new delegated administrator offers to clients in order to gain administrative control over the victim tenant.

## Detection

### Detection Analytics

**Analytic 1344**

Behavioral chain: (1) a login from a third-party account or untrusted source network establishes an interactive/remote session; (2) the session acquires elevated privileges or accesses sensitive resources atypical for that account; (3) subsequent lateral movement or data access occurs from the same session/device. Correlate Windows logon events, token elevation/privileged use, and resource access with third-party context.

**Analytic 1345**

Behavioral chain: (1) sshd or federated SSO logins from third-party networks or identities; (2) rapid sudo/su privilege elevation; (3) access to sensitive paths or east-west SSH. Correlate auth logs, process execution, and network flows.

**Analytic 1346**

Behavioral chain: (1) third-party interactive login or mobileconfig-based device enrollment; (2) privilege use or admin group change; (3) lateral movement mounts/ssh. Correlate unified logs and network telemetry.

**Analytic 1347**

Behavioral chain: (1) delegated admin or external identity establishes session (e.g., partner/reseller DAP, B2B guest, SAML/OAuth trust); (2) role elevation or app consent/permission grant; (3) downstream privileged actions in the tenant. Correlate IdP sign-in, admin/role assignment, and consent/admin-on-behalf events.

**Analytic 1348**

Behavioral chain: (1) cross-account or third-party principal assumes a role into the tenant/subscription/project; (2) privileged API calls are made in short succession; (3) access originates from unfamiliar networks or geos. Correlate assume-role/federation events with sensitive API usage.

**Analytic 1349**

Behavioral chain: (1) third-party app or admin connects via OAuth/marketplace install; (2) high-privilege scopes granted; (3) anomalous actions (mass read/exports, admin changes).

**Analytic 1350**

Behavioral chain: (1) delegated administration offers/relationships created or modified by partner tenants; (2) mailbox delegation/impersonation enabled; (3) follow-on access from partner IPs.


## Mitigations

### M1032 - Multi-factor Authentication

Require MFA for all delegated administrator accounts.

### M1030 - Network Segmentation

Network segmentation can be used to isolate infrastructure components that do not require broad network access.

### M1018 - User Account Management

Properly manage accounts and permissions used by parties in trusted relationships to minimize potential abuse by the party and if the party is compromised by an adversary. In Office 365 environments, partner relationships and roles can be viewed under the “Partner Relationships” page.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

### C0024 - SolarWinds Compromise

During the SolarWinds Compromise, APT29 gained access through compromised accounts at cloud solution partners, and used compromised certificates issued by Mimecast to authenticate to Mimecast customer systems.
