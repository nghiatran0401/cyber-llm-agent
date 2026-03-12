# T1552 - Unsecured Credentials

**Tactic:** Credential Access
**Platforms:** Containers, IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1552

## Description

Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. Shell History), operating system or application-specific repositories (e.g. Credentials in Registry),  or other specialized files/artifacts (e.g. Private Keys).

## Detection

### Detection Analytics

**Analytic 1153**

Unusual access to bash history, registry credentials paths, or private key files by unauthorized or scripting tools, with correlated file and process activity.

**Analytic 1154**

Reading of sensitive files like .bash_history, /etc/shadow, or private key directories by unauthorized users or unusual processes.

**Analytic 1155**

Unusual access to ~/Library/Keychains, ~/.bash_history, or Terminal command history by unauthorized processes or users.

**Analytic 1156**

Unusual web-based access or API scraping of password managers, single sign-on sessions, or credential sync services via browser automation or anomalous API tokens.

**Analytic 1157**

Unauthorized API or console calls to retrieve or reset password credentials, download key material, or modify SSO settings.

**Analytic 1158**

Access to container image layers or mounted secrets (e.g., Docker secrets) by processes not tied to entrypoint or orchestration context.

**Analytic 1159**

Use of configuration backup utilities or CLI access to dump plaintext passwords, local user hashes, or SNMP strings.


## Mitigations

### M1015 - Active Directory Configuration

Remove vulnerable Group Policy Preferences.

### M1047 - Audit

Preemptively search for files containing passwords or other credentials and take actions to reduce the exposure risk when found.

### M1041 - Encrypt Sensitive Information

When possible, store keys on separate cryptographic hardware instead of on the local system.

### M1037 - Filter Network Traffic

Limit access to the Instance Metadata API. A properly configured Web Application Firewall (WAF) may help prevent external adversaries from exploiting Server-side Request Forgery (SSRF) attacks that allow access to the Cloud Instance Metadata API.

### M1035 - Limit Access to Resource Over Network

Limit network access to sensitive services, such as the Instance Metadata API.

### M1028 - Operating System Configuration

There are multiple methods of preventing a user's command history from being flushed to their .bash_history file, including use of the following commands:
<code>set +o history</code> and <code>set -o history</code> to start logging again;
<code>unset HISTFILE</code> being added to a user's .bash_rc file; and
<code>ln -s /dev/null ~/.bash_history</code> to write commands to <code>/dev/null</code>instead.

### M1027 - Password Policies

Use strong passphrases for private keys to make cracking difficult. Do not store credentials within the Registry. Establish an organizational policy that prohibits password storage in files.

### M1026 - Privileged Account Management

If it is necessary that software must store credentials in the Registry, then ensure the associated accounts have limited permissions so they cannot be abused if obtained by an adversary.

### M1022 - Restrict File and Directory Permissions

Restrict file shares to specific directories with access only to necessary users.

### M1051 - Update Software

Apply patch KB2962486 which prevents credentials from being stored in GPPs.

### M1017 - User Training

Ensure that developers and system administrators are aware of the risk associated with having plaintext passwords in software configuration files that may be left on endpoint systems or servers.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0373 - Astaroth

Astaroth uses an external software known as NetPass to recover passwords.

### S1111 - DarkGate

DarkGate uses NirSoft tools to steal user credentials from the infected machine. NirSoft tools are executed via process hollowing in a newly-created instance of vbc.exe or regasm.exe.

### S1131 - NPPSPY

NPPSPY captures credentials by recording them through an alternative network listener registered to the <code>mpnotify.exe</code> process, allowing for cleartext recording of logon information.

### S1091 - Pacu

Pacu can search for sensitive data: for example, in Code Build environment variables, EC2 user data, and Cloud Formation templates.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0049 - Leviathan Australian Intrusions

Leviathan gathered credentials hardcoded in binaries located on victim devices during Leviathan Australian Intrusions.
