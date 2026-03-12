# T1222 - File and Directory Permissions Modification

**Tactic:** Defense Evasion
**Platforms:** ESXi, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1222

## Description

Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).

Modifications may include changing specific access rights, which may require taking ownership of a file or directory and/or elevated permissions depending on the file or directory’s existing permissions. This may enable malicious activity such as modifying, replacing, or deleting specific files or directories. Specific file and directory modifications may be a required step for many techniques, such as establishing Persistence via Accessibility Features, Boot or Logon Initialization Scripts, Unix Shell Configuration Modification, or tainting/hijacking other instrumental binary/configuration files via Hijack Execution Flow.

Adversaries may also change permissions of symbolic links. For example, malware (particularly ransomware) may modify symbolic links and associated settings to enable access to files from local shortcuts with remote paths.

## Detection

### Detection Analytics

**Analytic 0834**

Sequential behavioral chain of privilege escalation through permission modification: (1) Process creation of permission-modifying utilities (icacls, takeown, attrib, cacls), (2) Correlation with unusual user context or timing, (3) DACL modification events targeting sensitive files/directories, (4) Subsequent file access or modification attempts indicating successful privilege bypass

**Analytic 0835**

Behavioral sequence of unauthorized privilege escalation via permission modification: (1) chmod/chown/setfacl process execution with suspicious parameters, (2) Targeting of critical system files or unusual permission values, (3) Correlation with non-privileged user context or unusual timing patterns, (4) Follow-on file access indicating successful permission bypass

**Analytic 0836**

macOS-specific permission modification behavioral chain: (1) chmod/chown/chflags process execution, (2) System Integrity Protection (SIP) bypass attempts, (3) Extended attribute (xattr) modifications, (4) Unified log correlation with file system events, (5) Subsequent access to previously restricted resources

**Analytic 0837**

ESXi hypervisor permission modification behavioral chain: (1) SSH access to ESXi host, (2) chmod/chown execution on VMFS datastore files or system configuration, (3) Modification of VM configuration files (.vmx) or virtual disk permissions, (4) Hostd service log correlation, (5) vCenter permission change events if centrally managed


## Mitigations

### M1026 - Privileged Account Management

Ensure critical system files as well as those known to be abused by adversaries have restrictive permissions and are owned by an appropriately privileged account, especially if access is not required by users nor will inhibit system functionality.

### M1022 - Restrict File and Directory Permissions

Applying more restrictive permissions to files and directories could prevent adversaries from modifying their access control lists. Additionally, ensure that user settings regarding local and remote symbolic links are properly set or disabled where unneeded.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1242 - Qilin

Qilin can use symbolic links to redirect file paths for both remote and local objects.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
