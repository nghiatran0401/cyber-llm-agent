# T1053 - Scheduled Task/Job

**Tactic:** Execution, Persistence, Privilege Escalation
**Platforms:** Containers, ESXi, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1053

## Description

Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically may require being a member of an admin or otherwise privileged group on the remote system.

Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account (such as one with elevated permissions/privileges). Similar to System Binary Proxy Execution, adversaries have also abused task scheduling to potentially mask one-time execution under a trusted system process.

## Detection

### Detection Analytics

**Analytic 0258**

Detects creation or modification of scheduled tasks using schtasks.exe, at.exe, or COM objects followed by execution of outlier processes tied to the scheduled job.

**Analytic 0259**

Detects creation or modification of cron jobs via crontab, /etc/cron.* directories, or systemd timer units with execution by unusual users or non-standard intervals.

**Analytic 0260**

Detects creation or alteration of LaunchAgents or LaunchDaemons with corresponding plist modification followed by execution of associated binaries.

**Analytic 0261**

Detects unusual use of `cron` or `sleep` loops inside containers executing unfamiliar scripts or binaries repeatedly.

**Analytic 0262**

Detects modification of ESXi cron jobs, local.sh scripts, or scheduled API calls to persist custom binaries or shell scripts.


## Mitigations

### M1047 - Audit

Toolkits like the PowerSploit framework contain PowerUp modules that can be used to explore systems for permission weaknesses in scheduled tasks that could be used to escalate privileges.

### M1028 - Operating System Configuration

Configure settings for scheduled tasks to force tasks to run under the context of the authenticated account instead of allowing them to run as SYSTEM. The associated Registry key is located at <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SubmitControl</code>. The setting can be configured through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > Security Options: Domain Controller: Allow server operators to schedule tasks, set to disabled.

### M1026 - Privileged Account Management

Configure the Increase Scheduling Priority option to only allow the Administrators group the rights to schedule a priority process. This can be can be configured through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Increase scheduling priority.

### M1022 - Restrict File and Directory Permissions

Restrict access by setting directory and file permissions that are not specific to users or privileged accounts.

### M1018 - User Account Management

Limit privileges of user accounts and remediate Privilege Escalation vectors so only authorized administrators can create scheduled tasks on remote systems.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0447 - Lokibot

Lokibot's second stage DLL has set a timer using “timeSetEvent” to schedule its next execution.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
