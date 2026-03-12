# T1543 - Create or Modify System Process

**Tactic:** Persistence, Privilege Escalation
**Platforms:** Containers, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1543

## Description

Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these system processes are referred to as services. On macOS, launchd processes known as Launch Daemon and Launch Agent are run to finish system initialization and load user specific parameters. 

Adversaries may install new services, daemons, or agents that can be configured to execute at startup or a repeatable interval in order to establish persistence. Similarly, adversaries may modify existing services, daemons, or agents to achieve the same effect.  

Services, daemons, or agents may be created with administrator privileges but executed under root/SYSTEM privileges. Adversaries may leverage this functionality to create or modify system processes in order to escalate privileges.

## Detection

### Detection Analytics

**Analytic 1575**

Detects command-line or API-based creation/modification of Windows Services via `sc.exe`, `powershell.exe`, `services.exe`, or `ChangeServiceConfig`. Looks for creation/modification of autostart services via registry changes, file drops to `System32\services`, and anomalous parent-child process trees.

**Analytic 1576**

Detects creation or modification of `systemd` service units, addition of cron jobs that invoke binaries on boot, or suspicious writes to `/etc/init.d/`. Monitors `chmod +x` and `systemctl` execution paths, especially from non-root parent processes.

**Analytic 1577**

Detects creation or modification of `LaunchDaemon` or `LaunchAgent` plist files under `/Library/LaunchDaemons/`, `~/Library/LaunchAgents/`, or similar. Monitors execution of `launchctl`, property list edits, and file permission changes.

**Analytic 1578**

Detects creation of new container system processes via `docker run --restart`, `kubectl exec` to init containers, or modification of container init specs. Flags container images that override entrypoints to embed persistence behaviors.


## Mitigations

### M1047 - Audit

Use auditing tools capable of detecting privilege and service abuse opportunities on systems within an enterprise and correct them.

### M1040 - Behavior Prevention on Endpoint

On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent an application from writing a signed vulnerable driver to the system. On Windows 10 and 11, enable Microsoft Vulnerable Driver Blocklist to assist in hardening against third party-developed drivers.

### M1045 - Code Signing

Enforce registration and execution of only legitimately signed service drivers where possible.

### M1033 - Limit Software Installation

Restrict software installation to trusted repositories only and be cautious of orphaned software packages.

### M1028 - Operating System Configuration

Ensure that Driver Signature Enforcement is enabled to restrict unsigned drivers from being installed.

### M1026 - Privileged Account Management

Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root.

### M1022 - Restrict File and Directory Permissions

Restrict read/write access to system-level process files to only select privileged users who have a legitimate need to manage system services.

### M1054 - Software Configuration

Where possible, consider enforcing the use of container services in rootless mode to limit the possibility of privilege escalation or malicious effects on the host running the container.

### M1018 - User Account Management

Limit privileges of user accounts and groups so that only authorized administrators can interact with system-level process changes and service configurations.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1194 - Akira _v2

Akira _v2 can create a child process for encryption.

### S1184 - BOLDMOVE

BOLDMOVE can free all resources and terminate itself on victim machines.

### S0401 - Exaramel for Linux

Exaramel for Linux has a hardcoded location that it uses to achieve persistence if the startup system is Upstart or System V and it is running as root.

### S1152 - IMAPLoader

IMAPLoader modifies Windows tasks on the victim machine to reference a retrieved PE file through a path modification.

### S1121 - LITTLELAMB.WOOLTEA

LITTLELAMB.WOOLTEA can initialize itself as a daemon to run persistently in the background.

### S1142 - LunarMail

LunarMail can create an arbitrary process with a specified command line and redirect its output to a staging directory.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
