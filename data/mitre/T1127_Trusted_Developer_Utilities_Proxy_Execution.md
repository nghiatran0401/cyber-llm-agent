# T1127 - Trusted Developer Utilities Proxy Execution

**Tactic:** Defense Evasion
**Platforms:** Windows
**Reference:** https://attack.mitre.org/techniques/T1127

## Description

Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads. There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering. These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application control solutions.

Smart App Control is a feature of Windows that blocks applications it considers potentially malicious from running by verifying unsigned applications against a known safe list from a Microsoft cloud service before executing them. However, adversaries may leverage "reputation hijacking" to abuse an operating system’s trust of safe, signed applications that support the execution of arbitrary code. By leveraging Trusted Developer Utilities Proxy Execution to run their malicious code, adversaries may bypass Smart App Control protections.

## Detection

### Detection Analytics

**Analytic 0488**

A trusted/signed developer utility (parent) is executed in a non-developer context and (a) spawns suspicious children (e.g., powershell.exe, cmd.exe, rundll32.exe, regsvr32.exe, wscript.exe), (b) loads unsigned/user-writable DLLs, (c) writes and then runs a new PE from user-writable paths, and/or (d) immediately makes outbound network connections.


## Mitigations

### M1042 - Disable or Remove Feature or Program

Specific developer utilities may not be necessary within a given environment and should be removed if not used.

### M1038 - Execution Prevention

Certain developer utilities should be blocked or restricted if not required.

### M1021 - Restrict Web-Based Content

Consider disabling software installation or execution from the internet via developer utilities.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
