# T1087 - Account Discovery

**Tactic:** Discovery
**Platforms:** ESXi, IaaS, Identity Provider, Linux, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1087

## Description

Adversaries may attempt to get a listing of valid accounts, usernames, or email addresses on a system or within a compromised environment. This information can help adversaries determine which accounts exist, which can aid in follow-on behavior such as brute-forcing, spear-phishing attacks, or account takeovers (e.g., Valid Accounts).

Adversaries may use several methods to enumerate accounts, including abuse of existing tools, built-in commands, and potential misconfigurations that leak account names and roles or permissions in the targeted environment.

For examples, cloud environments typically provide easily accessible interfaces to obtain user lists. On hosts, adversaries can use default PowerShell and other command line functionality to identify accounts. Information about email addresses and accounts may also be extracted by searching an infected system’s files.

## Detection

### Detection Analytics

**Analytic 1612**

Detection of suspicious enumeration of local or domain accounts via command-line tools, WMI, or scripts.

**Analytic 1613**

Enumeration of users and groups through suspicious shell commands or unauthorized access to /etc/passwd or /etc/shadow.

**Analytic 1614**

Detection of user account enumeration through tools like dscl, dscacheutil, or loginshell enumeration via command-line.

**Analytic 1615**

Detection of API calls listing users, IAM roles, or groups in cloud environments.

**Analytic 1616**

Enumeration of user or role objects via IdP API endpoints or LDAP queries.

**Analytic 1617**

Account enumeration via esxcli, vim-cmd, or API calls to vSphere.

**Analytic 1618**

Account enumeration via bulk access to user directory features or hidden APIs.

**Analytic 1619**

Account discovery via VBA macros, COM objects, or embedded scripting.


## Mitigations

### M1028 - Operating System Configuration

Prevent administrator accounts from being enumerated when an application is elevating through UAC since it can lead to the disclosure of account names. The Registry key is located <code>HKLM\ SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators</code>. It can be disabled through GPO: Computer Configuration > [Policies] > Administrative Templates > Windows Components > Credential User Interface: E numerate administrator accounts on elevation.

### M1018 - User Account Management

Manage the creation, modification, use, and permissions associated to user accounts.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1229 - Havoc

Havoc can identify privileged user accounts on infected systems.

### S0445 - ShimRatReporter

ShimRatReporter listed all non-privileged and privileged accounts available on the machine.

### S1239 - TONESHELL

TONESHELL included functionality to retrieve a list of user accounts.

### S1065 - Woody RAT

Woody RAT can identify administrator accounts on an infected machine.

### S0658 - XCSSET

XCSSET attempts to discover accounts from various locations such as a user's Evernote, AppleID, Telegram, Skype, and WeChat data.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0024 - SolarWinds Compromise

During the SolarWinds Compromise, APT29 obtained a list of users and their roles from an Exchange server using `Get-ManagementRoleAssignment`.
