# T1556 - Modify Authentication Process

**Tactic:** Credential Access, Defense Evasion, Persistence
**Platforms:** IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1556

## Description

Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins on MacOS systems, responsible for gathering, storing, and validating credentials. By modifying an authentication process, an adversary may be able to authenticate to a service or system without using Valid Accounts.

Adversaries may maliciously modify a part of this process to either reveal credentials or bypass authentication mechanisms. Compromised credentials or access may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop.

## Detection

### Detection Analytics

**Analytic 0287**

Detects modification of LSASS and authentication DLLs, suspicious registry changes to password filter packages, and abnormal process access to lsass.exe. Correlates registry modifications, DLL loads, and process handle access events.

**Analytic 0288**

Detects modification of PAM configuration files, unauthorized new PAM modules, and suspicious process execution accessing PAM-related binaries. Correlates file modification events in /etc/pam.d/ with process execution of unauthorized binaries.

**Analytic 0289**

Detects unauthorized additions or changes to /Library/Security/SecurityAgentPlugins and suspicious process activity attempting to hook authentication APIs. Correlates file modifications with abnormal plugin loads in authentication flows.

**Analytic 0290**

Detects suspicious configuration changes in IdP authentication flows such as enabling reversible password encryption, MFA bypass, or policy weakening. Correlates policy modification events with unusual administrative activity.

**Analytic 0291**

Detects unauthorized changes to IAM authentication configurations such as disabling MFA, creating backdoor access keys, or altering trust policies. Correlates identity policy updates with unusual login behavior.


## Mitigations

### M1047 - Audit

Review authentication logs to ensure that mechanisms such as enforcement of MFA are functioning as intended.

Periodically review the hybrid identity solution in use for any discrepancies. For example, review all Pass Through Authentication (PTA) agents in the Azure Management Portal to identify any unwanted or unapproved ones. If ADFS is in use, review DLLs and executable files in the AD FS and Global Assembly Cache directories to ensure that they are signed by Microsoft. Note that in some cases binaries may be catalog-signed, which may cause the file to appear unsigned when viewing file properties.

Periodically review for new and unknown network provider DLLs within the Registry (`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\<NetworkProviderName>\NetworkProvider\ProviderPath`). Ensure only valid network provider DLLs are registered. The name of these can be found in the Registry key at `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order`, and have corresponding service subkey pointing to a DLL at `HKEY_LOCAL_MACHINE\SYSTEM\CurrentC ontrolSet\Services\<NetworkProviderName>\NetworkProvider`.

### M1032 - Multi-factor Authentication

Integrating multi-factor authentication (MFA) as part of organizational policy can greatly reduce the risk of an adversary gaining control of valid credentials that may be used for additional tactics such as initial access, lateral movement, and collecting information. MFA can also be used to restrict access to cloud resources and APIs.

### M1028 - Operating System Configuration

Ensure only valid password filters are registered. Filter DLLs must be present in Windows installation directory (`C:\Windows\System32\` by default) of a domain controller and/or local computer with a corresponding entry in `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages`. 

Starting in Windows 11 22H2, the `EnableMPRNotifications` policy can be disabled through Group Policy or through a configuration service provider to prevent Winlogon from sending credentials to network providers.

### M1027 - Password Policies

Ensure that <code>AllowReversiblePasswordEncryption</code> property is set to disabled unless there are application requirements.

### M1026 - Privileged Account Management

Audit domain and local accounts as well as their permission levels routinely to look for situations that could allow an adversary to gain wide access by obtaining credentials of a privileged account. These audits should also include if default accounts have been enabled, or if new local accounts are created that have not be authorized. Follow best practices for design and administration of an enterprise network to limit privileged account use across administrative tiers.

Limit access to the root account and prevent users from modifying protected components through proper privilege separation (ex SELinux, grsecurity, AppArmor, etc.) and limiting Privilege Escalation opportunities.

Limit on-premises accounts with access to the hybrid identity solution in place. For example, limit Azure AD Global Administrator accounts to only those required, and ensure that these are dedicated cloud-only accounts rather than hybrid ones.

### M1025 - Privileged Process Integrity

Enabled features, such as Protected Process Light (PPL), for LSA.

### M1022 - Restrict File and Directory Permissions

Restrict write access to the `/Library/Security/SecurityAgentPlugins` directory.

### M1024 - Restrict Registry Permissions

Restrict Registry permissions to disallow the modification of sensitive Registry keys such as `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order`.

### M1018 - User Account Management

Ensure that proper policies are implemented to dictate the the secure enrollment and deactivation of authentication mechanisms, such as MFA, for user accounts.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0377 - Ebury

Ebury can intercept private keys using a trojanized <code>ssh-add</code> function.

### S0487 - Kessel

Kessel has trojanized the <sode>ssh_login</code> and <code>user-auth_pubkey</code> functions to steal plaintext credentials.

### S0692 - SILENTTRINITY

SILENTTRINITY can create a backdoor in KeePass using a malicious config file and in TortoiseSVN using a registry hook.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0046 - ArcaneDoor

ArcaneDoor included modification of the AAA process to bypass authentication mechanisms.
