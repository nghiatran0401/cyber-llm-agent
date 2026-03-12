# T1548 - Abuse Elevation Control Mechanism

**Tactic:** Defense Evasion, Privilege Escalation
**Platforms:** IaaS, Identity Provider, Linux, Office Suite, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1548

## Description

Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.

## Detection

### Detection Analytics

**Analytic 0975**

Correlate registry modifications (e.g., UAC bypass registry keys), unusual parent-child process relationships (e.g., control.exe spawning cmd.exe), and unsigned elevated process executions with non-standard tokens or elevation flags.

**Analytic 0976**

Monitor audit logs for setuid/setgid bit changes, executions where UID ≠ EUID (indicative of sudo or privilege escalation), and high-integrity binaries launched by unprivileged users.

**Analytic 0977**

Detect execution of `/usr/libexec/security_authtrampoline` or use of AuthorizationExecuteWithPrivileges API, and monitor process lineage for unusual launches of GUI apps with escalated privileges.

**Analytic 0978**

Monitor for unexpected privilege elevation operations via SAML assertion manipulation, role injection, or changes to identity mappings that result in access escalation.

**Analytic 0979**

Detect sudden privilege escalations such as IAM role changes, user-assigned privilege boundaries, or elevation via assumed roles beyond normal behavior.


## Mitigations

### M1047 - Audit

Check for common UAC bypass weaknesses on Windows systems to be aware of the risk posture and address issues where appropriate.

### M1038 - Execution Prevention

System settings can prevent applications from running that haven't been downloaded from legitimate repositories which may help mitigate some of these issues. Not allowing unsigned applications from being run may also mitigate some risk.

### M1028 - Operating System Configuration

Applications with known vulnerabilities or known shell escapes should not have the setuid or setgid bits set to reduce potential damage if an application is compromised. Additionally, the number of programs with setuid or setgid bits set should be minimized across a system. Ensuring that the sudo tty_tickets setting is enabled will prevent this leakage across tty sessions.

### M1026 - Privileged Account Management

Remove users from the local administrator group on systems.

By requiring a password, even if an adversary can get terminal access, they must know the password to run anything in the sudoers file. Setting the timestamp_timeout to 0 will require the user to input their password every time sudo is executed.

### M1022 - Restrict File and Directory Permissions

The sudoers file should be strictly edited such that passwords are always required and that users can't spawn risky processes as users with higher privilege.

### M1051 - Update Software

Perform regular software updates to mitigate exploitation risk.

### M1052 - User Account Control

Although UAC bypass techniques exist, it is still prudent to use the highest enforcement level for UAC when possible and mitigate bypass opportunities that exist with techniques such as DLL.

### M1018 - User Account Management

Limit the privileges of cloud accounts to assume, create, or impersonate additional roles, policies, and permissions to only those required. Where just-in-time access is enabled, consider requiring manual approval for temporary elevation of privileges.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1130 - Raspberry Robin

Raspberry Robin implements a variation of the <code>ucmDccwCOMMethod</code> technique abusing the Windows AutoElevate backdoor to bypass UAC while elevating privileges.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
