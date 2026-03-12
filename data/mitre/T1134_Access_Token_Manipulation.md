# T1134 - Access Token Manipulation

**Tactic:** Defense Evasion, Privilege Escalation
**Platforms:** Windows
**Reference:** https://attack.mitre.org/techniques/T1134

## Description

Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls. Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it is the child of a different process or belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token.

An adversary can use built-in Windows API functions to copy access tokens from existing processes; this is known as token stealing. These token can then be applied to an existing process (i.e. Token Impersonation/Theft) or used to spawn a new process (i.e. Create Process with Token). An adversary must already be in a privileged user context (i.e. administrator) to steal a token. However, adversaries commonly use token stealing to elevate their security context from the administrator level to the SYSTEM level. An adversary can then use a token to authenticate to a remote system as the account for that token if the account has appropriate permissions on the remote system.

Any standard user can use the <code>runas</code> command, and the Windows API functions, to create impersonation tokens; it does not require access to an administrator account. There are also other mechanisms, such as Active Directory fields, that can be used to modify access tokens.

## Detection

### Detection Analytics

**Analytic 0786**

Detection of suspicious token manipulation chains: use of token-related APIs (e.g., LogonUser, DuplicateTokenEx) or commands (runas) → spawning of a new process under a different security context (e.g., SYSTEM) → mismatched parent-child process lineage or anomalies in Event Tracing for Windows (ETW) token/PPID data → abnormal lateral or privilege escalation activity.


## Mitigations

### M1026 - Privileged Account Management

Limit permissions so that users and user groups cannot create tokens. This setting should be defined for the local system account only. GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Create a token object. Also define who can create a process level token to only the local and network service through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Replace a process level token.

Administrators should log in as a standard user but run their tools with administrator privileges using the built-in access token manipulation command <code>runas</code>.

### M1018 - User Account Management

An adversary must already have administrator level access on the local system to make full use of this technique; be sure to restrict users and accounts to the least privileges they require.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0622 - AppleSeed

AppleSeed can gain system level privilege by passing <code>SeDebugPrivilege</code> to the <code>AdjustTokenPrivilege</code> API.

### S1068 - BlackCat

BlackCat has the ability modify access tokens.

### S0625 - Cuba

Cuba has used <code>SeDebugPrivilege</code> and <code>AdjustTokenPrivileges</code> to elevate privileges.

### S0038 - Duqu

Duqu examines running system processes for tokens that have specific system privileges. If it finds one, it will copy the token and store it for later use. Eventually it will start new processes with the stored token attached. It can also steal tokens to acquire administrative privileges.

### S0363 - Empire

Empire can use PowerSploit's <code>Invoke-TokenManipulation</code> to manipulate access tokens.

### S0666 - Gelsemium

Gelsemium can use token manipulation to bypass UAC on Windows7 systems.

### S0697 - HermeticWiper

HermeticWiper can use `AdjustTokenPrivileges` to grant itself privileges for debugging with `SeDebugPrivilege`, creating backups with `SeBackupPrivilege`, loading drivers with `SeLoadDriverPrivilege`, and shutting down a local system with `SeShutdownPrivilege`.

### S0203 - Hydraq

Hydraq creates a backdoor through which remote attackers can adjust token privileges.

### S0607 - KillDisk

KillDisk has attempted to get the access token of a process by calling <code>OpenProcessToken</code>. If KillDisk gets the access token, then it attempt to modify the token privileges with <code>AdjustTokenPrivileges</code>.

### S1060 - Mafalda

Mafalda can use `AdjustTokenPrivileges()` to elevate privileges.

### S0576 - MegaCortex

MegaCortex can enable <code>SeDebugPrivilege</code> and adjust token privileges.

### S0378 - PoshC2

PoshC2 can use Invoke-TokenManipulation for manipulating tokens.

### S0194 - PowerSploit

PowerSploit's <code>Invoke-TokenManipulation</code> Exfiltration module can be used to manipulate tokens.

### S1242 - Qilin

Qilin can use an embedded Mimikatz module for token manipulation.

### S0446 - Ryuk

Ryuk has attempted to adjust its token privileges to have the <code>SeDebugPrivilege</code>.

### S0562 - SUNSPOT

SUNSPOT modified its security token to grants itself debugging privileges by adding <code>SeDebugPrivilege</code>.

### S1210 - Sagerunex

Sagerunex finds the `explorer.exe` process after execution and uses it to change the token of its executing thread.

### S0633 - Sliver

Sliver has the ability to manipulate user tokens on targeted Windows systems.

### S0058 - SslMM

SslMM contains a feature to manipulate process privileges and tokens.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0017 - C0017

During C0017, APT41 used a ConfuserEx obfuscated BADPOTATO exploit to abuse named-pipe impersonation for local `NT AUTHORITY\SYSTEM` privilege escalation.
