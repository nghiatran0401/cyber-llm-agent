# T1566 - Phishing

**Tactic:** Initial Access
**Platforms:** Identity Provider, Linux, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1566

## Description

Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary. More generally, adversaries can conduct non-targeted phishing, such as in mass malware spam campaigns.

Adversaries may send victims emails containing malicious attachments or links, typically to execute malicious code on victim systems. Phishing may also be conducted via third-party services, like social media platforms. Phishing may also involve social engineering techniques, such as posing as a trusted source, as well as evasive techniques such as removing or manipulating emails or metadata/headers from compromised accounts being abused to send messages (e.g., Email Hiding Rules). Another way to accomplish this is by Email Spoofing the identity of the sender, which can be used to fool both the human recipient as well as automated security tools, or by including the intended target as a party to an existing email thread that includes malicious files or links (i.e., "thread hijacking").

Victims may also receive phishing messages that instruct them to call a phone number where they are directed to visit a malicious URL, download malware, or install adversary-accessible remote management tools onto their computer (i.e., User Execution).

## Detection

### Detection Analytics

**Analytic 0188**

Unusual inbound email activity where attachments or embedded URLs are delivered to users followed by execution of new processes or suspicious document behavior. Detection involves correlating email metadata, file creation, and network activity after a phishing message is received.

**Analytic 0189**

Monitor for malicious payload delivery through phishing where attachments or URLs in email clients (e.g., Thunderbird, mutt) result in unusual file creation or outbound network connections. Focus on correlation between mail logs, file writes, and execution activity.

**Analytic 0190**

Detection of phishing through anomalous Mail app activity, such as attachments saved to disk and immediately executed, or Safari/Preview launching URLs and files linked from email messages. Correlate UnifiedLogs events with subsequent process execution.

**Analytic 0191**

Phishing via Office documents containing embedded macros or links that spawn processes. Detection relies on correlating Office application logs with suspicious child process execution and outbound network connections.

**Analytic 0192**

Phishing attempts targeting IdPs often manifest as anomalous login attempts from suspicious email invitations or fake SSO prompts. Detection correlates login flows, MFA bypass attempts, and anomalous geographic patterns following phishing email delivery.

**Analytic 0193**

Phishing delivered via SaaS services (chat, collaboration platforms) where messages contain malicious URLs or attachments. Detect anomalous link clicks, suspicious file uploads, or token misuse after SaaS-based phishing attempts.


## Mitigations

### M1049 - Antivirus/Antimalware

Anti-virus can automatically quarantine suspicious files.

### M1047 - Audit

Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses.

### M1031 - Network Intrusion Prevention

Network intrusion prevention systems and systems designed to scan and remove malicious email attachments or links can be used to block activity.

### M1021 - Restrict Web-Based Content

Determine if certain websites or attachment types (ex: .scr, .exe, .pif, .cpl, etc.) that can be used for phishing are necessary for business operations and consider blocking access if activity cannot be monitored well or if it poses a significant risk.

### M1054 - Software Configuration

Use anti-spoofing and email authentication mechanisms to filter messages based on validity checks of the sender domain (using SPF) and integrity of messages (using DKIM). Enabling these mechanisms within an organization (through policies such as DMARC) may enable recipients (intra-org and cross domain) to perform similar message filtering and validation.

### M1017 - User Training

Users can be trained to identify social engineering techniques and phishing emails.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0009 - Hikit

Hikit has been spread through spear phishing.

### S1139 - INC Ransomware

INC Ransomware campaigns have used spearphishing emails for initial access.

### S1073 - Royal

Royal has been spread through the use of phishing campaigns including "call back phishing" where victims are lured into calling a number provided through email.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
