# T1672 - Email Spoofing

**Tactic:** Defense Evasion
**Platforms:** Linux, Office Suite, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1672

## Description

Adversaries may fake, or spoof, a sender’s identity by modifying the value of relevant email headers in order to establish contact with victims under false pretenses. In addition to actual email content, email headers (such as the FROM header, which contains the email address of the sender) may also be modified. Email clients display these headers when emails appear in a victim's inbox, which may cause modified emails to appear as if they were from the spoofed entity. 

This behavior may succeed when the spoofed entity either does not enable or enforce identity authentication tools such as Sender Policy Framework (SPF), DomainKeys Identified Mail (DKIM), and/or Domain-based Message Authentication, Reporting and Conformance (DMARC). Even if SPF and DKIM are configured properly, spoofing may still succeed when a domain sets a weak DMARC policy such as `v=DMARC1; p=none; fo=1;`. This means that while DMARC is technically present, email servers are not instructed to take any filtering action when emails fail authentication checks.

Adversaries may abuse Microsoft 365’s Direct Send functionality to spoof internal users by using internal devices like printers to send emails without authentication. Adversaries may also abuse absent or weakly configured SPF, SKIM, and/or DMARC policies to conceal social engineering attempts such as Phishing. They may also leverage email spoofing for Impersonation of legitimate external individuals and organizations, such as journalists and academics.

## Detection

### Detection Analytics

**Analytic 1202**

Monitor email message traces and headers for failed SPF, DKIM, or DMARC checks indicating spoofed sender identities. Correlate abnormal sender domains or mismatched return-paths with elevated spoofing likelihood.

**Analytic 1203**

Detects spoofed emails by analyzing mail server logs (e.g., Postfix, Sendmail) for mismatched header fields, failed SPF/DKIM checks, and anomalies in SMTP proxy logs. Defender observes discrepancies between sending domain, return-path domain, and message metadata.

**Analytic 1204**

Detects suspicious inbound mail traffic where SPF/DKIM/DMARC authentication fails or where sender and return-path domains mismatch, observable in Apple Mail unified logs or MDM-controlled logging pipelines.

**Analytic 1205**

Correlates Office 365 or Google Workspace audit logs for spoofed sender addresses, failed email authentication, and anomalies in message delivery metadata. Defender observes failed SPF/DKIM checks and domain mismatches tied to suspicious campaigns.


## Mitigations

### M1054 - Software Configuration

Use anti-spoofing and email authentication mechanisms to filter messages based on validity checks of the sender domain (using SPF) and integrity of messages (using DKIM). Enabling these mechanisms within an organization (through policies such as DMARC) may enable recipients (intra-org and cross domain) to perform similar message filtering and validation.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
