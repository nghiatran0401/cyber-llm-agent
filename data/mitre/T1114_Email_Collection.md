# T1114 - Email Collection

**Tactic:** Collection
**Platforms:** Linux, Office Suite, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1114

## Description

Adversaries may target user email to collect sensitive information. Emails may contain sensitive data, including trade secrets or personal information, that can prove valuable to adversaries. Emails may also contain details of ongoing incident response operations, which may allow adversaries to adjust their techniques in order to maintain persistence or evade defenses. Adversaries can collect or forward email from mail servers or clients.

## Detection

### Detection Analytics

**Analytic 1309**

Correlates creation of email forwarding rules or header anomalies (e.g., X-MS-Exchange-Organization-AutoForwarded) with suspicious process execution, file access of .pst/.ost files, and network connections to external SMTP servers.

**Analytic 1310**

Detects file access to mbox/maildir files in conjunction with curl/wget/postfix execution, or anomalous shell scripts harvesting user mail directories.

**Analytic 1311**

Monitors Mail.app database or maildir file access, automation via AppleScript, and abnormal mail rule creation using scripting or UI automation frameworks.

**Analytic 1312**

Correlates unusual auto-forwarding rule creation via Exchange Web Services or Outlook rules engine, presence of X-MS-Exchange-Organization-AutoForwarded headers, and logon session anomalies from abnormal IPs.


## Mitigations

### M1047 - Audit

Enterprise email solutions have monitoring mechanisms that may include the ability to audit auto-forwarding rules on a regular basis.

In an Exchange environment, Administrators can use Get-InboxRule to discover and remove potentially malicious auto-forwarding rules.

### M1041 - Encrypt Sensitive Information

Use of encryption provides an added layer of security to sensitive information sent over email. Encryption using public key cryptography requires the adversary to obtain the private certificate along with an encryption key to decrypt messages.

### M1032 - Multi-factor Authentication

Use of multi-factor authentication for public-facing webmail servers is a recommended best practice to minimize the usefulness of usernames and passwords to adversaries.

### M1060 - Out-of-Band Communications Channel

Use secure out-of-band authentication methods to verify the authenticity of critical actions initiated via email, such as password resets, financial transactions, or access requests. For highly sensitive information, utilize out-of-band communication channels instead of relying solely on email to prevent adversaries from collecting data through compromised email accounts.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0367 - Emotet

Emotet has been observed leveraging a module that can scrape email addresses from Outlook.

### S1201 - TRANSLATEXT

TRANSLATEXT has exfiltrated collected email addresses to the C2 server.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
