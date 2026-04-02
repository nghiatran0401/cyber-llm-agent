# T1484 - Domain or Tenant Policy Modification

**Tactic:** Defense Evasion, Privilege Escalation
**Platforms:** Identity Provider, Windows
**Reference:** https://attack.mitre.org/techniques/T1484

## Description

Adversaries may modify the configuration settings of a domain or identity tenant to evade defenses and/or escalate privileges in centrally managed environments. Such services provide a centralized means of managing identity resources such as devices and accounts, and often include configuration settings that may apply between domains or tenants such as trust relationships, identity syncing, or identity federation.

Modifications to domain or tenant settings may include altering domain Group Policy Objects (GPOs) in Microsoft Active Directory (AD) or changing trust settings for domains, including federation trusts relationships between domains or tenants.

With sufficient permissions, adversaries can modify domain or tenant policy settings. Since configuration settings for these services apply to a large number of identity resources, there are a great number of potential attacks malicious outcomes that can stem from this abuse. Examples of such abuse include:  

* modifying GPOs to push a malicious Scheduled Task to computers throughout the domain environment
* modifying domain trusts to include an adversary-controlled domain, allowing adversaries to  forge access tokens that will subsequently be accepted by victim domain resources
* changing configuration settings within the AD environment to implement a Rogue Domain Controller.
* adding new, adversary-controlled federated identity providers to identity tenants, allowing adversaries to authenticate as any user managed by the victim tenant

Adversaries may temporarily modify domain or tenant policy, carry out a malicious action(s), and then revert the change to remove suspicious indicators.

## Detection

### Detection Analytics

**Analytic 0755**

Adversary modifies Group Policy Objects (GPOs), domain trust, or directory service objects via GUI, CLI, or programmatic APIs. Behavior includes creation/modification of GPOs, delegation permissions, trust objects, or rogue domain controller registration.

**Analytic 0756**

Adversary modifies tenant policy through changes to federation configuration, trust settings, or identity provider additions in Microsoft 365/AzureAD via Portal, PowerShell, or Graph API. Includes setting authentication to federated or updating federated domains.


## Mitigations

### M1047 - Audit

Identify and correct GPO permissions abuse opportunities (ex: GPO modification privileges) using auditing tools such as BloodHound (version 1.5.1 and later).

### M1026 - Privileged Account Management

Use least privilege and protect administrative access to the Domain Controller and Active Directory Federation Services (AD FS) server. Do not create service accounts with administrative privileges.

### M1018 - User Account Management

Consider implementing WMI and security filtering to further tailor which users and computers a GPO will apply to.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
