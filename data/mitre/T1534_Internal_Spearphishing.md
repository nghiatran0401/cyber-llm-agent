# T1534 - Internal Spearphishing

**Tactic:** Lateral Movement
**Platforms:** Linux, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1534

## Description

After they already have access to accounts or systems within the environment, adversaries may use internal spearphishing to gain access to additional information or compromise other users within the same organization. Internal spearphishing is multi-staged campaign where a legitimate account is initially compromised either by controlling the user's device or by compromising the account credentials of the user. Adversaries may then attempt to take advantage of the trusted internal account to increase the likelihood of tricking more victims into falling for phish attempts, often incorporating Impersonation.

For example, adversaries may leverage Spearphishing Attachment or Spearphishing Link as part of internal spearphishing to deliver a payload or redirect to an external site to capture credentials through Input Capture on sites that mimic login interfaces.

Adversaries may also leverage internal chat apps, such as Microsoft Teams, to spread malicious content or engage users in attempts to capture sensitive information and/or credentials.

## Detection

### Detection Analytics

**Analytic 0147**

Sequence of internal email sent from a recently compromised user account (preceded by abnormal logon or device activity), with attachments or links leading to execution or credential harvesting. Defender observes: internal mail delivery to peers with high entropy attachments, followed by click events, process initiation, or credential prompts.

**Analytic 0148**

Delivery of suspicious internal communication (e.g., Thunderbird, Evolution) using compromised internal accounts. Sequence of: unexpected user activity + mail transfer logs + download or execution of attachments.

**Analytic 0149**

Abnormal Apple Mail use, including internal email relays followed by file execution or script events (e.g., attachments launched via Preview, terminal triggered from Mail.app)

**Analytic 0150**

Internal spearphishing via SaaS applications (e.g., Slack, Teams, Gmail): message sent from compromised user with attachment or URL, followed by click and credential access behavior.

**Analytic 0151**

Outlook or Word used to forward suspicious internal attachments with macro content. Defender observes attachment forwarding, auto-opening behaviors, or macro prompt interactions.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

### C0022 - Operation Dream Job

During Operation Dream Job, Lazarus Group conducted internal spearphishing from within a compromised organization.
