# T1562 - Impair Defenses

**Tactic:** Defense Evasion
**Platforms:** Containers, ESXi, IaaS, Identity Provider, Linux, Network Devices, Office Suite, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1562

## Description

Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms. This not only involves impairing preventative defenses, such as firewalls and anti-virus, but also detection capabilities that defenders can use to audit activity and identify malicious behavior. This may also span both native defenses as well as supplemental capabilities installed by users and administrators.

Adversaries may also impair routine operations that contribute to defensive hygiene, such as blocking users from logging out, preventing a system from shutting down, or disabling or modifying the update process. Adversaries could also target event aggregation and analysis mechanisms, or otherwise disrupt these procedures by altering other system components. These restrictions can further enable malicious operations as well as the continued propagation of incidents.

## Detection

### Detection Analytics

**Analytic 0886**

Unusual service stop events, termination of AV/EDR processes, registry modifications disabling security tools, and firewall/defender configuration changes. Correlate process creation with service stop requests and registry edits.

**Analytic 0887**

Execution of commands that stop or kill processes associated with logging or security daemons (auditd, syslog, falco). Detect modifications to iptables or disabling SELinux/AppArmor enforcement. Correlate sudo/root context with abrupt service halts.

**Analytic 0888**

Execution of commands or APIs that disable Gatekeeper, XProtect, or system integrity protections. Detect configuration changes through unified logs. Monitor termination of system security daemons (e.g., syspolicyd).

**Analytic 0889**

Modification of container runtime security profiles (AppArmor, seccomp) or removal of monitoring agents within containers. Detect unauthorized mounting/unmounting of host /proc or /sys to disable logging or auditing.

**Analytic 0890**

Unusual ESXi shell commands disabling syslog forwarding or stopping hostd/vpxa daemons. Detect modifications to firewall rules on ESXi host or disabling of lockdown mode.

**Analytic 0891**

Cloud control plane actions disabling security services (CloudTrail logging, GuardDuty, Security Hub). Detect IAM role abuse correlating with service disable events.

**Analytic 0892**

Changes to security configurations such as disabling MFA requirements, reducing session token lifetimes, or turning off risk-based policies. Correlate admin logins with sudden policy downgrades.

**Analytic 0893**

Execution of commands disabling AAA, logging, or security features on routers/switches. Detect privilege escalation followed by config changes that disable defense mechanisms.

**Analytic 0894**

Disabling of security macros or safe mode settings within Word/Excel/Outlook. Detect registry edits or configuration file changes that weaken macro enforcement.


## Mitigations

### M1047 - Audit

Routinely check account role permissions to ensure only expected users and roles have permission to modify defensive tools and settings. Periodically verify that tools such as EDRs are functioning as expected.

### M1042 - Disable or Remove Feature or Program

Consider removing previous versions of tools that are unnecessary to the environment when possible.

### M1038 - Execution Prevention

Use application control where appropriate, especially regarding the execution of tools outside of the organization's security policies (such as rootkit removal tools) that have been abused to impair system defenses. Ensure that only approved security applications are used and running on enterprise systems.

### M1022 - Restrict File and Directory Permissions

Ensure proper process and file permissions are in place to prevent adversaries from disabling or interfering with security/logging services.

### M1024 - Restrict Registry Permissions

Ensure proper Registry permissions are in place to prevent adversaries from disabling or interfering with security/logging services.

### M1054 - Software Configuration

Consider implementing policies on internal web servers, such HTTP Strict Transport Security, that enforce the use of HTTPS/network traffic encryption to prevent insecure connections.

### M1018 - User Account Management

Ensure proper user permissions are in place to prevent adversaries from disabling or interfering with security/logging services.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1184 - BOLDMOVE

BOLDMOVE can modify proprietary Fortinet logs on victim machines.

### S1206 - JumbledPath

JumbledPath can impair logging on all devices used along its connection path to compromised hosts.

### S0603 - Stuxnet

Stuxnet reduces the integrity level of objects to allow write actions.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
