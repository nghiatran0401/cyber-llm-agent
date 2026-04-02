# T1569 - System Services

**Tactic:** Execution
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1569

## Description

Adversaries may abuse system services or daemons to execute commands or programs. Adversaries can execute malicious content by interacting with or creating services either locally or remotely. Many services are set to run at boot, which can aid in achieving persistence (Create or Modify System Process), but adversaries can also abuse services for one-time or temporary execution.

## Detection

### Detection Analytics

**Analytic 0778**

Monitor for abnormal creation or modification of Windows services (e.g., via sc.exe, PowerShell, or API calls) that load non-standard executables. Correlate registry changes in service keys with service creation events and process execution to detect service abuse for persistence or execution.

**Analytic 0779**

Detect unusual invocations of systemctl, service, or init scripts creating or modifying daemons. Monitor audit logs for execution of binaries from unexpected paths linked to service start/stop activity.

**Analytic 0780**

Monitor launchd service definitions and property list (.plist) modifications for non-standard executables. Detect unauthorized processes registered as launch daemons or agents.


## Mitigations

### M1040 - Behavior Prevention on Endpoint

On Windows 10, enable Attack Surface Reduction (ASR) rules to block processes created by PsExec from running.

### M1026 - Privileged Account Management

Ensure that permissions disallow services that run at a higher permissions level from being created or interacted with by a user with a lower permission level.

### M1022 - Restrict File and Directory Permissions

Ensure that high permission level service binaries cannot be replaced or modified by users with a lower permission level.

### M1018 - User Account Management

Prevent users from installing their own launch agents or launch daemons.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
