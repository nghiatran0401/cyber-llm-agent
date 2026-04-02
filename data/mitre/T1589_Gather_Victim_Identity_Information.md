# T1589 - Gather Victim Identity Information

**Tactic:** Reconnaissance
**Platforms:** PRE
**Reference:** https://attack.mitre.org/techniques/T1589

## Description

Adversaries may gather information about the victim's identity that can be used during targeting. Information about identities may include a variety of details, including personal data (ex: employee names, email addresses, security question responses, etc.) as well as sensitive details such as credentials or multi-factor authentication (MFA) configurations.

Adversaries may gather this information in various ways, such as direct elicitation via Phishing for Information. Information about users could also be enumerated via other active means (i.e. Active Scanning) such as probing and analyzing responses from authentication services that may reveal valid usernames in a system or permitted MFA /methods associated with those usernames. Information about victims may also be exposed to adversaries via online or other accessible data sets (ex: Social Media or Search Victim-Owned Websites).

Gathering this information may reveal opportunities for other forms of reconnaissance (ex: Search Open Websites/Domains or Phishing for Information), establishing operational resources (ex: Compromise Accounts), and/or initial access (ex: Phishing or Valid Accounts).

## Detection

### Detection Analytics

**Analytic 1973**

Monitor for suspicious network traffic that could be indicative of probing for user information, such as large/iterative quantities of authentication requests originating from a single source (especially if the source is known to be associated with an adversary/botnet). Analyzing web metadata may also reveal artifacts that can be attributed to potentially malicious activity, such as referer or user-agent string HTTP/S fields.


## Mitigations

### M1056 - Pre-compromise

This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Efforts should focus on minimizing the amount and sensitivity of data available to external parties.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

### C0022 - Operation Dream Job

For Operation Dream Job, Lazarus Group conducted extensive reconnaissance research on potential targets.

### C0014 - Operation Wocao

During Operation Wocao, threat actors targeted people based on their organizational roles and privileges.
