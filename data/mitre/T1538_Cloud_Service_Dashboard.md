# T1538 - Cloud Service Dashboard

**Tactic:** Discovery
**Platforms:** IaaS, Identity Provider, Office Suite, SaaS
**Reference:** https://attack.mitre.org/techniques/T1538

## Description

An adversary may use a cloud service dashboard GUI with stolen credentials to gain useful information from an operational cloud environment, such as specific services, resources, and features. For example, the GCP Command Center can be used to view all assets, review findings of potential security risks, and run additional queries, such as finding public IP addresses and open ports.

Depending on the configuration of the environment, an adversary may be able to enumerate more information via the graphical dashboard than an API. This also allows the adversary to gain information without manually making any API requests.

## Detection

### Detection Analytics

**Analytic 0808**

Detects web console login events followed by read-only or metadata retrieval activity from GUI sources (e.g., browser session, mobile client) rather than API/CLI sources. Correlates across CloudTrail, IAM identity logs, and user-agent context.

**Analytic 0809**

Detects successful login to cloud identity portals (e.g., Okta, Azure AD, Google Identity) from atypical geolocations, devices, or user agents immediately followed by dashboard/portal navigation to sensitive pages such as user or app configuration.

**Analytic 0810**

Detects login to admin consoles (e.g., Microsoft 365 Admin Center) from unrecognized users, devices, or geolocations followed by non-API data review or configuration read actions that suggest GUI dashboard use.

**Analytic 0811**

Detects SaaS web login followed by dashboard or web GUI page views from unfamiliar locations, devices, or access patterns. Identifies use of sensitive reporting or configuration consoles accessed from high-risk accounts.


## Mitigations

### M1018 - User Account Management

Enforce the principle of least-privilege by limiting dashboard visibility to only the resources required. This may limit the discovery value of the dashboard in the event of a compromised account.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
