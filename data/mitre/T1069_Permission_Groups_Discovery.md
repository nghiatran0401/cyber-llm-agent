# T1069 - Permission Groups Discovery

**Tactic:** Discovery
**Platforms:** Containers, IaaS, Identity Provider, Linux, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1069

## Description

Adversaries may attempt to discover group and permission settings. This information can help adversaries determine which user accounts and groups are available, the membership of users in particular groups, and which users and groups have elevated permissions.

Adversaries may attempt to discover group permission settings in many different ways. This data may provide the adversary with information about the compromised environment that can be used in follow-on activity and targeting.

## Detection

### Detection Analytics

**Analytic 0507**

Detection of adversary enumeration of domain or local group memberships via native tools such as net.exe, PowerShell, or WMI. This activity may precede lateral movement or privilege escalation.

**Analytic 0508**

Detection of group enumeration using commands like 'id', 'groups', or 'getent group', often followed by privilege escalation or SSH lateral movement.

**Analytic 0509**

Group membership checks via 'dscl', 'dscacheutil', or 'id', typically executed via terminal or automation scripts.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0335 - Carbon

Carbon uses the <code>net group</code> command.

### S0483 - IcedID

IcedID has the ability to identify Workgroup membership.

### S0233 - MURKYTOP

MURKYTOP has the capability to retrieve information about groups.

### S0445 - ShimRatReporter

ShimRatReporter gathered the local privileges for the infected host.

### S0623 - Siloscape

Siloscape checks for Kubernetes node permissions.

### S0266 - TrickBot

TrickBot can identify the groups the user on a compromised host belongs to.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0024 - SolarWinds Compromise

During the SolarWinds Compromise, APT29 used the `Get-ManagementRoleAssignment` PowerShell cmdlet to enumerate Exchange management role assignments through an Exchange Management Shell.
