# T1678 - Delay Execution

**Tactic:** Defense Evasion
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1678

## Description

Adversaries may employ various time-based methods to evade detection and analysis. These techniques often exploit system clocks, delays, or timing mechanisms to obscure malicious activity, blend in with benign activity, and avoid scrutiny. Adversaries can perform this behavior within virtualization/sandbox environments or natively on host systems. 

Adversaries may utilize programmatic `sleep` commands or native system scheduling functionality, for example Scheduled Task/Job. Benign commands or other operations may also be used to delay malware execution or ensure prior commands have had time to execute properly. Loops or otherwise needless repetitions of commands, such as `ping`, may be used to delay malware execution and potentially exceed time thresholds of automated analysis environments. Another variation, commonly referred to as API hammering, involves making various calls to Native API functions in order to delay execution (while also potentially overloading analysis environments with junk data).

## Detection

### Detection Analytics

**Analytic 1048**

Correlated use of sleep/delay mechanisms (e.g., kernel32!Sleep, NTDLL APIs) in short-lived processes, combined with parent processes invoking suspicious scripts (e.g., wscript, powershell) with minimal user interaction.

**Analytic 1049**

Shell scripts or binaries invoking repeated 'sleep', 'ping', or low-level syscalls (e.g., nanosleep) in short-lived execution chains with no user or system interaction. Frequently seen in malicious cron jobs or payload stagers.

**Analytic 1050**

Execution of AppleScript, bash, or launchd jobs that invoke delay functions (e.g., sleep, delay in AppleScript) with limited parent interaction and staged follow-on commands.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1230 - HIUPAN

HIUPAN has used a config file “$.ini” to store a sleep multiplier to execute at a set interval value prior to initiating a watcher function that checks for a specific running process, that checks for removable drives and installs itself and supporting files if one is available.

### S1239 - TONESHELL

TONESHELL has the ability to pause operations for a specified duration prior to follow-on execution of activities.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0057 - 3CX Supply Chain Attack

During the 3CX Supply Chain Attack, AppleJeus's software generates a randomly selected date that is between 1-4 weeks in the future. This timestamp is then checked against the current time of the compromised machine, and the malware will sleep until that time is encountered.
