# T1531 - Account Access Removal

**Tactic:** Impact
**Platforms:** ESXi, IaaS, Linux, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1531

## Description

Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. Accounts may be deleted, locked, or manipulated (ex: changed credentials, revoked permissions for SaaS platforms such as Sharepoint) to remove access to accounts. Adversaries may also subsequently log off and/or perform a System Shutdown/Reboot to set malicious changes into place.

In Windows, Net utility, <code>Set-LocalUser</code> and <code>Set-ADAccountPassword</code> PowerShell cmdlets may be used by adversaries to modify user accounts. Accounts could also be disabled by Group Policy. In Linux, the <code>passwd</code> utility may be used to change passwords. On ESXi servers, accounts can be removed or modified via esxcli (`system account set`, `system account remove`).

Adversaries who use ransomware or similar attacks may first perform this and other Impact behaviors, such as Data Destruction and Defacement, in order to impede incident response/recovery before completing the Data Encrypted for Impact objective.

## Detection

### Detection Analytics

**Analytic 0334**

Correlated user account modification (reset, disable, deletion) events with anomalous process lineage (e.g., PowerShell or net.exe from an interactive session), especially outside of IT admin change windows or by non-admin users.

**Analytic 0335**

Password changes or account deletions via 'passwd', 'userdel', or 'chage' preceded by interactive shell or remote command execution from non-privileged accounts.

**Analytic 0336**

Execution of dscl or sysadminctl commands to disable, delete, or modify users combined with anomalous process ancestry or terminal session launch.

**Analytic 0337**

Invocation of esxcli 'system account remove' from vCLI, SSH, or vSphere API with anomalous user access or outside maintenance windows.

**Analytic 0338**

O365 UnifiedAuditLog entries for Remove-Mailbox or Set-Mailbox with account disable or delete actions correlated with suspicious login locations or MFA bypass.

**Analytic 0339**

Deletion or disablement of user accounts in platforms like Okta, Salesforce, or Zoom with anomalies in admin session attributes or mass actions within short duration.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1134 - DEADWOOD

DEADWOOD changes the password for local and domain users via <code>net.exe</code> to a random 32 character string to prevent these accounts from logging on. Additionally, DEADWOOD will terminate the <code>winlogon.exe</code> process to prevent attempts to log on to the infected system.

### S0372 - LockerGoga

LockerGoga has been observed changing account passwords and logging off current users.

### S0576 - MegaCortex

MegaCortex has changed user account passwords and logged users off the system.

### S0688 - Meteor

Meteor has the ability to change the password of local users on compromised hosts and can log off users.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
