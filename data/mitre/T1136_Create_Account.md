# T1136 - Create Account

**Tactic:** Persistence
**Platforms:** Containers, ESXi, IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1136

## Description

Adversaries may create an account to maintain access to victim systems. With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

Accounts may be created on the local system or within a domain or cloud tenant. In cloud environments, adversaries may create accounts that only have access to specific services, which can reduce the chance of detection.

## Detection

### Detection Analytics

**Analytic 1604**

Adversary uses built-in OS tools or API calls to create local or domain accounts for persistence or lateral movement. Tools such as 'net user', PowerShell, or MMC snap-ins may be used. Detection focuses on Event ID 4720 paired with process lineage and user context.

**Analytic 1605**

Adversary invokes 'useradd', 'adduser', or equivalent system commands or scripts to create local users. Detection focuses on command execution and audit trail of passwd/shadow file modifications.

**Analytic 1606**

Adversary creates new users using 'dscl' commands, GUI tools, or by modifying user plist files. Detection includes monitoring dscl invocation and user-related plist changes.

**Analytic 1607**

Adversary creates users via IAM/IdP API or portal (e.g., Azure AD, Okta). Detection involves monitoring API calls, admin action logs, and correlation with role assignments.

**Analytic 1608**

Account creation via cloud service APIs or CLI, often associated with key generation. Monitored via CloudTrail or equivalent audit logs.


## Mitigations

### M1032 - Multi-factor Authentication

Use multi-factor authentication for user and privileged accounts.

### M1030 - Network Segmentation

Configure access controls and firewalls to limit access to domain controllers and systems used to create and manage accounts.

### M1028 - Operating System Configuration

Protect domain controllers by ensuring proper security configuration for critical servers.

### M1026 - Privileged Account Management

Limit the number of accounts with permissions to create other accounts. Do not allow domain administrator accounts to be used for day-to-day operations that may expose them to potential adversaries on unprivileged systems.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1199 - LockBit 2.0

LockBit 2.0 has been observed creating accounts for persistence using simple names like "a".

## Threat Groups

_No threat groups documented._

## Campaigns

### C0025 - 2016 Ukraine Electric Power Attack

During the 2016 Ukraine Electric Power Attack, Sandworm Team added a login to a SQL Server with `sp_addlinkedsrvlogin`.
