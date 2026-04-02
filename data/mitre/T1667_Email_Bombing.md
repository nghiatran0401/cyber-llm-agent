# T1667 - Email Bombing

**Tactic:** Impact
**Platforms:** Linux, Office Suite, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1667

## Description

Adversaries may flood targeted email addresses with an overwhelming volume of messages. This may bury legitimate emails in a flood of spam and disrupt business operations.

An adversary may accomplish email bombing by leveraging an automated bot to register a targeted address for e-mail lists that do not validate new signups, such as online newsletters. The result can be a wave of thousands of e-mails that effectively overloads the victim’s inbox.

By sending hundreds or thousands of e-mails in quick succession, adversaries may successfully divert attention away from and bury legitimate messages including security alerts, daily business processes like help desk tickets and client correspondence, or ongoing scams. This behavior can also be used as a tool of harassment.

This behavior may be a precursor for Spearphishing Voice. For example, an adversary may email bomb a target and then follow up with a phone call to fraudulently offer assistance. This social engineering may lead to the use of Remote Access Software to steal credentials, deploy ransomware, conduct Financial Theft, or engage in other malicious activity.

## Detection

### Detection Analytics

**Analytic 1008**

Detect abnormally high volume of inbound email messages or repetitive attachments being delivered to a single mailbox within a short time window. Defenders should look for anomalous spikes in message counts and repetitive attachment file creation events correlated with targeted users.

**Analytic 1009**

Monitor mail server logs (e.g., Postfix, Sendmail) for excessive connections or inbound message counts targeting a single recipient. Correlate with repetitive attachment storage in /var/mail or /var/spool/mail directories.

**Analytic 1010**

Detect abnormal use of email clients (e.g., Outlook, Thunderbird) showing mass arrival of messages or repetitive attachments being locally stored. Correlate message volume with file creation activity in mail cache directories.

**Analytic 1011**

Monitor unified logs and Mail.app activity for repetitive incoming messages with attachments. Defenders should look for large volumes of incoming mail stored under ~/Library/Mail with unusual timing or repetitive subjects.


## Mitigations

### M1054 - Software Configuration

Use anti-spoofing and email authentication mechanisms to filter messages based on validity checks of the sender domain (using SPF) and integrity of messages (using DKIM). Enabling these mechanisms within an organization (through policies such as DMARC) may enable recipients (intra-org and cross domain) to perform similar message filtering and validation. Note that additional filtering may be necessary if emails are coming from legitimate sources.

### M1017 - User Training

Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful social engineering via e-mail bombing.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
