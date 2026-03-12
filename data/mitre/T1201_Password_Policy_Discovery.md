# T1201 - Password Policy Discovery

**Tactic:** Discovery
**Platforms:** IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1201

## Description

Adversaries may attempt to access detailed information about the password policy used within an enterprise network or cloud environment. Password policies are a way to enforce complex passwords that are difficult to guess or crack through Brute Force. This information may help the adversary to create a list of common passwords and launch dictionary and/or brute force attacks which adheres to the policy (e.g. if the minimum password length should be 8, then not trying passwords such as 'pass123'; not checking for more than 3-4 passwords per account if the lockout is set to 6 as to not lock out accounts).

Password policies can be set and discovered on Windows, Linux, and macOS systems via various command shell utilities such as <code>net accounts (/domain)</code>, <code>Get-ADDefaultDomainPasswordPolicy</code>, <code>chage -l <username></code>, <code>cat /etc/pam.d/common-password</code>, and <code>pwpolicy getaccountpolicies</code>. Adversaries may also leverage a Network Device CLI on network devices to discover password policy information (e.g. <code>show aaa</code>, <code>show aaa common-criteria policy all</code>).

Password policies can be discovered in cloud environments using available APIs such as <code>GetAccountPasswordPolicy</code> in AWS.

## Detection

### Detection Analytics

**Analytic 0455**

Cause→effect chain: (1) a user or service spawns a shell/PowerShell that queries local/domain password policy via commands/cmdlets (e.g., `net accounts`, `Get-ADDefaultDomainPasswordPolicy`, `secedit /export`); (2) optional directory/LDAP reads from DCs; (3) same principal performs adjacent Discovery or credential-related actions within a short window. Correlate sysmon process creation with PowerShell ScriptBlock and Security logs.

**Analytic 0456**

Chain: (1) interactive/non-interactive `chage -l`, `grep`/`cat` of PAM config (e.g., `/etc/pam.d/common-password`, `/etc/security/pwquality.conf`); (2) optional reads of `/etc/login.defs`; (3) same user performs account enumeration or password change attempts shortly after. Use auditd `execve` and file read events plus shell history collection.

**Analytic 0457**

Chain: (1) execution of `pwpolicy` or MDM/DirectoryService reads of account policies; (2) optional read of `/Library/Preferences/com.apple.loginwindow` or config profiles; (3) follow-on credential probing or lateral movement by same user/session. Use unified logs and process telemetry.

**Analytic 0458**

Chain: (1) cloud API calls that fetch tenant/organization password policy (e.g., AWS `GetAccountPasswordPolicy`, GCP/OCI equivalents or IAM settings reads); (2) within a short window, the same principal creates users, rotates creds, or changes auth settings. Use cloud audit logs.

**Analytic 0459**

Chain: (1) IdP policy/read operations by a principal (e.g., Microsoft Entra/Graph requests to read password or authentication policies); (2) adjacent risky changes (role assignment, app consent) by same principal. Use IdP audit logs.

**Analytic 0460**

Chain: (1) SaaS admin API or PowerShell remote session reads tenant password/authentication settings (e.g., M365 Unified Audit Log ‘Cmdlet’ with `Get-MsolPasswordPolicy`/`Get-OrganizationConfig` parameters that expose password settings); (2) same session proceeds to mailbox or tenant changes.

**Analytic 0461**

Chain: (1) privileged CLI sessions run read-only commands that dump AAA/password policies (e.g., `show aaa`, `show password-policy`); (2) same account changes AAA or user DB shortly after. Use network device AAA/command accounting or syslog.


## Mitigations

### M1027 - Password Policies

Ensure only valid password filters are registered. Filter DLLs must be present in Windows installation directory (<code>C:\Windows\System32\</code> by default) of a domain controller and/or local computer with a corresponding entry in <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages</code>.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0488 - CrackMapExec

CrackMapExec can discover the password policies applied to the target system.

### S0236 - Kwampirs

Kwampirs collects password policy information with the command <code>net accounts</code>.

### S0039 - Net

The <code>net accounts</code> and <code>net accounts /domain</code> commands with Net can be used to obtain password policy information.

### S0378 - PoshC2

PoshC2 can use <code>Get-PassPol</code> to enumerate the domain password policy.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0012 - Operation CuckooBees

During Operation CuckooBees, the threat actors used the `net accounts` command as part of their advanced reconnaissance.
