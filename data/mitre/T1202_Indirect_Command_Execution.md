# T1202 - Indirect Command Execution

**Tactic:** Defense Evasion
**Platforms:** Windows
**Reference:** https://attack.mitre.org/techniques/T1202

## Description

Adversaries may abuse utilities that allow for command execution to bypass security restrictions that limit the use of command-line interpreters. Various Windows utilities may be used to execute commands, possibly without invoking cmd. For example, Forfiles, the Program Compatibility Assistant (`pcalua.exe`), components of the Windows Subsystem for Linux (WSL), `Scriptrunner.exe`, as well as other utilities may invoke the execution of programs and commands from a Command and Scripting Interpreter, Run window, or via scripts. Adversaries may also abuse the `ssh.exe` binary to execute malicious commands via the `ProxyCommand` and `LocalCommand` options, which can be invoked via the `-o` flag or by modifying the SSH config file.

Adversaries may abuse these features for Defense Evasion, specifically to perform arbitrary execution while subverting detections and/or mitigation controls (such as Group Policy) that limit/prevent the usage of cmd or file extensions more commonly associated with malicious payloads.

## Detection

### Detection Analytics

**Analytic 0576**

Cause→effect chain: (1) A user or service launches an indirection utility (e.g., forfiles.exe, pcalua.exe, wsl.exe, scriptrunner.exe, ssh.exe with -o ProxyCommand/LocalCommand). (2) That utility spawns a secondary program/command (PowerShell, cmd, msiexec, regsvr32, curl, arbitrary EXE) and/or opens outbound network connections. (3) Optional precursor modification of SSH config to persist LocalCommand/ProxyCommand. Correlate process creation, command/script content, file access to %USERPROFILE%\.ssh\config, and network connections from the utility or its child.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0193 - Forfiles

Forfiles can be used to subvert controls and possibly conceal command execution by not directly invoking cmd.

### S0379 - Revenge RAT

Revenge RAT uses the Forfiles utility to execute commands on the system.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
