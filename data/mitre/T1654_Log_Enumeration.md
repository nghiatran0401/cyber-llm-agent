# T1654 - Log Enumeration

**Tactic:** Discovery
**Platforms:** ESXi, IaaS, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1654

## Description

Adversaries may enumerate system and service logs to find useful data. These logs may highlight various types of valuable insights for an adversary, such as user authentication records (Account Discovery), security or vulnerable software (Software Discovery), or hosts within a compromised network (Remote System Discovery).

Host binaries may be leveraged to collect system logs. Examples include using `wevtutil.exe` or PowerShell on Windows to access and/or export security event information. In cloud environments, adversaries may leverage utilities such as the Azure VM Agent’s `CollectGuestLogs.exe` to collect security logs from cloud hosted infrastructure.

Adversaries may also target centralized logging infrastructure such as SIEMs. Logs may also be bulk exported and sent to adversary-controlled infrastructure for offline analysis.

In addition to gaining a better understanding of the environment, adversaries may also monitor logs in real time to track incident response procedures. This may allow them to adjust their techniques in order to maintain persistence or evade defenses.

## Detection

### Detection Analytics

**Analytic 0705**

Monitor for use of native utilities such as wevtutil.exe or PowerShell cmdlets (Get-WinEvent, Get-EventLog) to enumerate or export logs. Unusual access to security or system event channels, especially by non-administrative users or processes, should be correlated with subsequent file export or network transfer activity.

**Analytic 0706**

Monitor for suspicious use of commands such as cat, less, grep, or journalctl accessing /var/log/ files. Abnormal enumeration of authentication logs (auth.log, secure) or bulk access to multiple logs in short time windows should be flagged.

**Analytic 0707**

Detect abnormal access to unified logs via log show or fs_usage targeting system log files. Monitor for execution of shell utilities (cat, grep) against /var/log/system.log and for plist modifications enabling verbose logging.

**Analytic 0708**

Monitor for cloud API calls that export or collect guest or system logs. Abnormal use of Azure VM Agent’s CollectGuestLogs.exe or AWS CloudWatch GetLogEvents across multiple instances should be correlated with lateral movement or data staging.

**Analytic 0709**

Monitor ESXi shell or API access to host logs under /var/log/. Abnormal enumeration of vmkernel.log, hostd.log, or vpxa.log by unauthorized accounts should be flagged.


## Mitigations

### M1018 - User Account Management

Limit the ability to access and export sensitive logs to privileged accounts where possible.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1194 - Akira _v2

Akira _v2 can enumerate the trace, debug, error, info, and warning logs on targeted systems.

### S1246 - BeaverTail

BeaverTail has identified .ldb and .log files stored in browser extension directories for collection and exfiltration.

### S1159 - DUSTTRAP

DUSTTRAP can identify infected system log information.

### S1191 - Megazord

Megazord has the ability to print the trace, debug, error, info, and warning logs.

### S1091 - Pacu

Pacu can collect CloudTrail event histories and CloudWatch logs.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
