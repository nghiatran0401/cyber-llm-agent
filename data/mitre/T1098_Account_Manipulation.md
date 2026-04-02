# T1098 - Account Manipulation

**Tactic:** Persistence, Privilege Escalation
**Platforms:** Containers, ESXi, IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1098

## Description

Adversaries may manipulate accounts to maintain and/or elevate access to victim systems. Account manipulation may consist of any action that preserves or modifies adversary access to a compromised account, such as modifying credentials or permission groups. These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials. 

In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain. However, account manipulation may also lead to privilege escalation where modifications grant access to additional roles, permissions, or higher-privileged Valid Accounts.

## Detection

### Detection Analytics

**Analytic 0265**

Account attribute changes (e.g., password set, group membership, servicePrincipalName, logon hours) correlated with unusual process lineage or timing, indicating privilege escalation or persistence via valid accounts.

**Analytic 0266**

Use of native tools or scripting (e.g., `usermod`, `passwd`, `groupmod`) to escalate permissions or persist access on existing users, correlated with login or process events.

**Analytic 0267**

Modifications to user accounts via `dscl`, `pwpolicy`, or System Preferences CLI (`sysadminctl`) that alter user groups, enable root, or bypass MDM restrictions.

**Analytic 0268**

Modifications to SSO/SAML user attributes (e.g., `isAdmin`, `role`, MFA bypass, App assignments) often through CLI, API, or rogue IdP apps.

**Analytic 0269**

Addition of new users or changes to role permissions (e.g., ReadOnly -> Admin) via API or vSphere Client, particularly from non-jumpbox IPs.

**Analytic 0270**

Role escalation (e.g., Editor → Owner) in cloud collaboration tools (Google Workspace, O365) or file sharing apps to maintain elevated access.


## Mitigations

### M1042 - Disable or Remove Feature or Program

Remove unnecessary and potentially abusable authentication and authorization mechanisms where possible.

### M1032 - Multi-factor Authentication

Use multi-factor authentication for user and privileged accounts.

### M1030 - Network Segmentation

Configure access controls and firewalls to limit access to critical systems and domain controllers. Most cloud environments support separate virtual private cloud (VPC) instances that enable further segmentation of cloud systems.

### M1028 - Operating System Configuration

Protect domain controllers by ensuring proper security configuration for critical servers to limit access by potentially unnecessary protocols and services, such as SMB file sharing.

### M1026 - Privileged Account Management

Do not allow domain administrator accounts to be used for day-to-day operations that may expose them to potential adversaries on unprivileged systems.

### M1022 - Restrict File and Directory Permissions

Restrict access to potentially sensitive files that deal with authentication and/or authorization.

### M1018 - User Account Management

Ensure that low-privileged user accounts do not have permissions to modify accounts or account-related policies.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0274 - Calisto

Calisto adds permissions and remote logins to all users.

### S0002 - Mimikatz

The Mimikatz credential dumper has been extended to include Skeleton Key domain controller authentication bypass functionality. The <code>LSADUMP::ChangeNTLM</code> and <code>LSADUMP::SetNTLM</code> modules can also manipulate the password hash of an account without knowing the clear text value.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0025 - 2016 Ukraine Electric Power Attack

During the 2016 Ukraine Electric Power Attack, Sandworm Team used the `sp_addlinkedsrvlogin` command in MS-SQL to create a link between a created account and other servers in the network.
