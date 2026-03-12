# T1482 - Domain Trust Discovery

**Tactic:** Discovery
**Platforms:** Windows
**Reference:** https://attack.mitre.org/techniques/T1482

## Description

Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments. Domain trusts provide a mechanism for a domain to allow access to resources based on the authentication procedures of another domain. Domain trusts allow the users of the trusted domain to access resources in the trusting domain. The information discovered may help the adversary conduct SID-History Injection, Pass the Ticket, and Kerberoasting. Domain trusts can be enumerated using the `DSEnumerateDomainTrusts()` Win32 API call, .NET methods, and LDAP. The Windows utility Nltest is known to be used by adversaries to enumerate domain trusts.

## Detection

### Detection Analytics

**Analytic 0016**

Adversary uses nltest, PowerShell, or Win32/.NET API to enumerate domain trust relationships (via DSEnumerateDomainTrusts, GetAllTrustRelationships, or LDAP queries), followed by discovery or authentication staging.


## Mitigations

### M1047 - Audit

Map the trusts within existing domains/forests and keep trust relationships to a minimum.

### M1030 - Network Segmentation

Employ network segmentation for sensitive domains..

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0552 - AdFind

AdFind can gather information about organizational units (OUs) and domain trusts from Active Directory.

### S1081 - BADHATCH

BADHATCH can use `nltest.exe /domain_trusts` to discover domain trust relationships on a compromised machine.

### S0534 - Bazar

Bazar can use Nltest tools to obtain information about the domain.

### S0521 - BloodHound

BloodHound has the ability to map domain trusts and identify misconfigurations for potential abuse.

### S1063 - Brute Ratel C4

Brute Ratel C4 can use LDAP queries and `nltest /domain_trusts` for domain trust discovery.

### S1159 - DUSTTRAP

DUSTTRAP can identify Active Directory information and related items.

### S0363 - Empire

Empire has modules for enumerating domain trusts.

### S0483 - IcedID

IcedID used Nltest during initial discovery.

### S1160 - Latrodectus

Latrodectus can run `C:\Windows\System32\cmd.exe /c nltest /domain_trusts` to discover domain trusts.

### S1146 - MgBot

MgBot includes modules for collecting information on local domain users and permissions.

### S0359 - Nltest

Nltest may be used to enumerate trusted domains by using commands such as <code>nltest /domain_trusts</code>.

### S1145 - Pikabot

Pikabot will gather information concerning the Windows Domain the victim machine is a member of during execution.

### S0378 - PoshC2

PoshC2 has modules for enumerating domain trusts.

### S0194 - PowerSploit

PowerSploit has modules such as <code>Get-NetDomainTrust</code> and <code>Get-NetForestTrust</code> to enumerate domain and forest trusts.

### S0650 - QakBot

QakBot can run <code>nltest /domain_trusts /all_trusts</code> for domain trust discovery.

### S1071 - Rubeus

Rubeus can gather information about domain trusts.

### S1124 - SocGholish

SocGholish can profile compromised systems to identify domain trust relationships.

### S0266 - TrickBot

TrickBot can gather information about domain trusts by utilizing Nltest.

### S0105 - dsquery

dsquery can be used to gather information on domain trusts with <code>dsquery * -filter "(objectClass=trustedDomain)" -attr *</code>.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0015 - C0015

During C0015, the threat actors used the command `nltest /domain_trusts /all_trusts` to enumerate domain trusts.

### C0049 - Leviathan Australian Intrusions

Leviathan performed Active Directory enumeration of victim environments during Leviathan Australian Intrusions.

### C0024 - SolarWinds Compromise

During the SolarWinds Compromise, APT29 used the `Get-AcceptedDomain` PowerShell cmdlet to enumerate accepted domains through an Exchange Management Shell. They also used AdFind to enumerate domains and to discover trust between federated domains.
