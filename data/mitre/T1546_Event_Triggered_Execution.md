# T1546 - Event Triggered Execution

**Tactic:** Persistence, Privilege Escalation
**Platforms:** IaaS, Linux, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1546

## Description

Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity such as running specific applications/binaries. Cloud environments may also support various functions and services that monitor and can be invoked in response to specific cloud events.

Adversaries may abuse these mechanisms as a means of maintaining persistent access to a victim via repeatedly executing malicious code. After gaining access to a victim system, adversaries may create/modify event triggers to point to malicious content that will be executed whenever the event trigger is invoked.

Since the execution can be proxied by an account with higher permissions, such as SYSTEM or service accounts, an adversary may be able to abuse these triggered execution mechanisms to escalate their privileges.

## Detection

### Detection Analytics

**Analytic 0024**

Correlates unexpected modifications to WMI event filters, scheduled task triggers, or registry autorun keys with subsequent execution of non-standard binaries by SYSTEM-level processes.

**Analytic 0025**

Detects inotify or auditd configuration changes that monitor system files coupled with execution of script interpreters or binaries by cron or systemd timers.

**Analytic 0026**

Correlates launchd plist modifications with subsequent unauthorized script execution or anomalous parent-child process trees involving user agents.

**Analytic 0027**

Monitors cloud function creation triggered by specific audit log events (e.g., IAM changes, object creation), followed by anomalous behavior from new service accounts.

**Analytic 0028**

Correlates Power Automate or similar logic app workflows triggered by SaaS file uploads or email rules with data forwarding or anomalous access patterns.

**Analytic 0029**

Detects macros or VBA triggers set to execute on document open or close events, often correlating with embedded payloads or C2 traffic shortly after execution.


## Mitigations

### M1026 - Privileged Account Management

Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root.

### M1051 - Update Software

Perform regular software updates to mitigate exploitation risk.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1091 - Pacu

Pacu can set up S3 bucket notifications to trigger a malicious Lambda function when a CloudFormation template is uploaded to the bucket. It can also create Lambda functions that trigger upon the creation of users, roles, and groups.

### S1164 - UPSTYLE

UPSTYLE creates a `.pth` file beginning with the text `import` so that any time another process or script attempts to reference the modified item the malicious code will also run.

### S0658 - XCSSET

XCSSET's `dfhsebxzod` module searches for `.xcodeproj` directories within the user’s home folder and subdirectories. For each match, it locates the corresponding `project.pbxproj` file and embeds an encoded payload into a build rule, target configuration, or project setting. The payload is later executed during the build process.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0035 - KV Botnet Activity

KV Botnet Activity involves managing events on victim systems via <code>libevent</code> to execute a callback function when any running process contains the following references in their path without also having a reference to <code>bioset</code>: busybox, wget, curl, tftp, telnetd, or lua. If the <code>bioset</code> string is not found, the related process is terminated.
