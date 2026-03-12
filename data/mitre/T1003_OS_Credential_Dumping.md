# T1003 - OS Credential Dumping

**Tactic:** Credential Access
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1003

## Description

Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password. Credentials can be obtained from OS caches, memory, or structures. Credentials can then be used to perform Lateral Movement and access restricted information.

Several of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.

## Detection

### Detection Analytics

**Analytic 0648**

Processes accessing LSASS memory or SAM registry hives outside of trusted security tools, often followed by file creation or lateral movement. Detects unauthorized access to sensitive OS subsystems for credential extraction.

**Analytic 0649**

Processes opening /proc/*/mem or /proc/*/maps targeting credential-storing services like sshd or login. Behavior often includes high privilege escalation and memory inspection tools such as gcore or gdb.

**Analytic 0650**

Unsigned processes accessing system memory or launching known credential scraping tools (e.g., osascript, dylib injections) to access the Keychain or sensitive memory regions.


## Mitigations

### M1015 - Active Directory Configuration

Manage the access control list for “Replicating Directory Changes All” and other permissions associated with domain controller replication. Consider adding users to the "Protected Users" Active Directory security group. This can help limit the caching of users' plaintext credentials.

### M1040 - Behavior Prevention on Endpoint

On Windows 10, enable Attack Surface Reduction (ASR) rules to secure LSASS and prevent credential stealing.

### M1043 - Credential Access Protection

With Windows 10, Microsoft implemented new protections called Credential Guard to protect the LSA secrets that can be used to obtain credentials through forms of credential dumping. It is not configured by default and has hardware and firmware system requirements. It also does not protect against all forms of credential dumping.

### M1041 - Encrypt Sensitive Information

Ensure Domain Controller backups are properly secured.

### M1028 - Operating System Configuration

Consider disabling or restricting NTLM. Consider disabling WDigest authentication.

### M1027 - Password Policies

Ensure that local administrator accounts have complex, unique passwords across all systems on the network.

### M1026 - Privileged Account Management

Windows:
Do not put user or admin domain accounts in the local administrator groups across systems unless they are tightly controlled, as this is often equivalent to having a local administrator account with the same password on all systems. Follow best practices for design and administration of an enterprise network to limit privileged account use across administrative tiers.

Linux:
Scraping the passwords from memory requires root privileges. Follow best practices in restricting access to privileged accounts to avoid hostile programs from accessing such sensitive regions of memory.

### M1025 - Privileged Process Integrity

On Windows 8.1 and Windows Server 2012 R2, enable Protected Process Light for LSA.

### M1017 - User Training

Limit credential overlap across accounts and systems by training users and administrators not to use the same password for multiple accounts.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0030 - Carbanak

Carbanak obtains Windows logon password details.

### S0232 - HOMEFRY

HOMEFRY can perform credential dumping.

### S1146 - MgBot

MgBot includes modules for dumping and capturing credentials from process memory.

### S0052 - OnionDuke

OnionDuke steals credentials from its victims.

### S0048 - PinchDuke

PinchDuke steals credentials from compromised hosts. PinchDuke's credential stealing functionality is believed to be based on the source code of the Pinch credential stealing malware (also known as LdPinch). Credentials targeted by PinchDuke include ones associated many sources such as WinInet Credential Cache, and Lightweight Directory Access Protocol (LDAP).

### S0379 - Revenge RAT

Revenge RAT has a plugin for credential harvesting.

### S0094 - Trojan.Karagany

Trojan.Karagany can dump passwords and save them into <code>\ProgramData\Mail\MailAg\pwds.txt</code>.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
