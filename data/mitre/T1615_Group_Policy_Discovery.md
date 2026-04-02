# T1615 - Group Policy Discovery

**Tactic:** Discovery
**Platforms:** Windows
**Reference:** https://attack.mitre.org/techniques/T1615

## Description

Adversaries may gather information on Group Policy settings to identify paths for privilege escalation, security measures applied within a domain, and to discover patterns in domain objects that can be manipulated or used to blend in the environment. Group Policy allows for centralized management of user and computer settings in Active Directory (AD). Group policy objects (GPOs) are containers for group policy settings made up of files stored within a predictable network path `\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\`.

Adversaries may use commands such as <code>gpresult</code> or various publicly available PowerShell functions, such as <code>Get-DomainGPO</code> and <code>Get-DomainGPOLocalGroup</code>, to gather information on Group Policy settings. Adversaries may use this information to shape follow-on behaviors, including determining potential attack paths within the target network as well as opportunities to manipulate Group Policy settings (i.e. Domain or Tenant Policy Modification) for their benefit.

## Detection

### Detection Analytics

**Analytic 0152**

Detection of adversary attempts to enumerate Group Policy settings through suspicious command execution (gpresult), PowerShell enumeration (Get-DomainGPO, Get-DomainGPOLocalGroup), and abnormal LDAP queries targeting groupPolicyContainer objects. Defenders observe unusual process lineage, script execution, or LDAP filter activity against domain controllers.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0521 - BloodHound

BloodHound has the ability to collect local admin information via GPO.

### S1159 - DUSTTRAP

DUSTTRAP can identify victim environment Group Policy information.

### S0082 - Emissary

Emissary has the capability to execute <code>gpresult</code>.

### S0363 - Empire

Empire includes various modules for enumerating Group Policy.

### S1141 - LunarWeb

LunarWeb can capture information on group policy settings

## Threat Groups

_No threat groups documented._

## Campaigns

### C0049 - Leviathan Australian Intrusions

Leviathan performed extensive Active Directory enumeration of victim environments during Leviathan Australian Intrusions.
