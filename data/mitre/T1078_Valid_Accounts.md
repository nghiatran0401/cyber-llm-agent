# T1078 - Valid Accounts

**Tactic:** Defense Evasion, Initial Access, Persistence, Privilege Escalation
**Platforms:** Containers, ESXi, IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1078

## Description

Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access, network devices, and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.

In some cases, adversaries may abuse inactive accounts: for example, those belonging to individuals who are no longer part of an organization. Using these accounts may allow the adversary to evade detection, as the original account user will not be present to identify any anomalous activity taking place on their account.

The overlap of permissions for local, domain, and cloud accounts across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise.

## Detection

### Detection Analytics

**Analytic 1543**

Detection of compromised or misused valid accounts via anomalous logon patterns, abnormal logon types, and inconsistent geographic or time-based activity across Windows endpoints.

**Analytic 1544**

Detection of valid account misuse through SSH logins, sudo/su abuse, and service account anomalies outside expected patterns.

**Analytic 1545**

Detection of interactive and remote logins by service accounts or users at unusual times, with unexpected child process activity.

**Analytic 1546**

Detection of valid account abuse in IdP logs via geographic anomalies, impossible travel, risky sign-ins, and multiple MFA attempts or failures.

**Analytic 1547**

Detection of containerized service accounts or compromised kubeconfigs being used for cluster access from unexpected nodes or IPs.


## Mitigations

### M1036 - Account Use Policies

Use conditional access policies to block logins from non-compliant devices or from outside defined organization IP ranges.

### M1015 - Active Directory Configuration

Disable legacy authentication, which does not support MFA, and require the use of modern authentication protocols instead.

### M1013 - Application Developer Guidance

Ensure that applications do not store sensitive data or credentials insecurely. (e.g. plaintext credentials in code, published credentials in repositories, or credentials in public cloud storage).

### M1032 - Multi-factor Authentication

Implement multi-factor authentication (MFA) across all account types, including default, local, domain, and cloud accounts, to prevent unauthorized access, even if credentials are compromised. MFA provides a critical layer of security by requiring multiple forms of verification beyond just a password. This measure significantly reduces the risk of adversaries abusing valid accounts to gain initial access, escalate privileges, maintain persistence, or evade defenses within your network.

### M1027 - Password Policies

Applications and appliances that utilize default username and password should be changed immediately after the installation, and before deployment to a production environment. When possible, applications that use SSH keys should be updated periodically and properly secured.

Policies should minimize (if not eliminate) reuse of passwords between different user accounts, especially employees using the same credentials for personal accounts that may not be defended by enterprise security resources.

### M1026 - Privileged Account Management

Audit domain and local accounts as well as their permission levels routinely to look for situations that could allow an adversary to gain wide access by obtaining credentials of a privileged account. These audits should also include if default accounts have been enabled, or if new local accounts are created that have not been authorized. Follow best practices for design and administration of an enterprise network to limit privileged account use across administrative tiers.

### M1018 - User Account Management

Regularly audit user accounts for activity and deactivate or remove any that are no longer needed.

### M1017 - User Training

Applications may send push notifications to verify a login as a form of multi-factor authentication (MFA). Train users to only accept valid push notifications and to report suspicious push notifications.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0567 - Dtrack

Dtrack used hard-coded credentials to gain access to a network share.

### S0038 - Duqu

Adversaries can instruct Duqu to spread laterally by copying itself to shares it has enumerated and for which it has obtained legitimate credentials (via keylogging or other means). The remote host is then infected by using the compromised credentials to schedule a task on remote machines that executes the malware.

### S0604 - Industroyer

Industroyer can use supplied user credentials to execute processes and stop services.

### S0599 - Kinsing

Kinsing has used valid SSH credentials to access remote hosts.

### S0362 - Linux Rabbit

Linux Rabbit acquires valid SSH accounts through brute force.

### S0053 - SeaDuke

Some SeaDuke samples have a module to extract email from Microsoft Exchange servers using compromised credentials.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0028 - 2015 Ukraine Electric Power Attack

During the 2015 Ukraine Electric Power Attack, Sandworm Team used valid accounts on the corporate network to escalate privileges, move laterally, and establish persistence within the corporate network.

### C0057 - 3CX Supply Chain Attack

During 3CX Supply Chain Attack, AppleJeus has gained access to the 3CX corporate environment through legitimate VPN credentials.

### C0032 - C0032

During the C0032 campaign, TEMP.Veles used compromised VPN accounts.

### C0038 - HomeLand Justice

During HomeLand Justice, threat actors used a compromised Exchange account to search mailboxes and create new Exchange accounts.

### C0049 - Leviathan Australian Intrusions

Leviathan used captured, valid account information to log into victim web applications and appliances during Leviathan Australian Intrusions.

### C0002 - Night Dragon

During Night Dragon, threat actors used compromised VPN accounts to gain access to victim systems.

### C0048 - Operation MidnightEclipse

During Operation MidnightEclipse, threat actors extracted sensitive credentials while moving laterally through compromised networks.

### C0014 - Operation Wocao

During Operation Wocao, threat actors used valid VPN credentials to gain initial access.

### C0056 - RedPenguin

During RedPenguin, UNC3886 used legitimate credentials to gain priviliged access to Juniper routers.

### C0024 - SolarWinds Compromise

During the SolarWinds Compromise, APT29 used different compromised credentials for remote access and to move laterally.
