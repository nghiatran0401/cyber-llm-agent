# T1564 - Hide Artifacts

**Tactic:** Defense Evasion
**Platforms:** ESXi, Linux, Office Suite, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1564

## Description

Adversaries may attempt to hide artifacts associated with their behaviors to evade detection. Operating systems may have features to hide various artifacts, such as important system files and administrative task execution, to avoid disrupting user work environments and prevent users from changing files or features on the system. Adversaries may abuse these features to hide artifacts such as files, directories, user accounts, or other system activity to evade detection.

Adversaries may also attempt to hide artifacts associated with malicious behavior by creating computing regions that are isolated from common security instrumentation, such as through the use of virtualization technology.

## Detection

### Detection Analytics

**Analytic 1384**

Abuse of file/registry attributes to hide malicious files, directories, or services. Defender view: detection of attrib.exe setting hidden/system flags, creation of Alternate Data Streams, or registry keys altering file visibility.

**Analytic 1385**

Hidden file creation using leading '.' or file attribute changes with chattr (immutable/hidden flags). Defender view: detect execution of chattr, lsattr anomalies, and unusual hidden files appearing in system directories.

**Analytic 1386**

Hidden files via 'chflags hidden' or Apple-specific attributes, LaunchAgents/LaunchDaemons placed in non-standard hidden directories. Defender view: detect command execution modifying file flags and unusual plist creation in hidden paths.

**Analytic 1387**

Abuse of VMFS or ESXi shell to hide datastore files, renaming/moving VMDK or VMX files into hidden directories. Defender view: anomalous ESXi shell commands or file operations obscuring VM artifacts.

**Analytic 1388**

Malicious macros or embedded objects hidden within Office documents by renaming streams or using hidden OLE objects. Defender view: detection of hidden macro streams or objects in documents correlated with anomalous execution.


## Mitigations

### M1049 - Antivirus/Antimalware

Review and audit file/folder exclusions, and limit scope of exclusions to only what is required where possible.

### M1013 - Application Developer Guidance

Application developers should consider limiting the requirements for custom or otherwise difficult to manage file/folder exclusions. Where possible, install applications to trusted system folder paths that are already protected by restricted file and directory permissions.

### M1047 - Audit

Periodically audit virtual machines for abnormalities.

### M1033 - Limit Software Installation

Restrict the installation of software that may be abused to create hidden desktops, such as hVNC, to user groups that require it.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0482 - Bundlore

Bundlore uses the <code>mktemp</code> utility to make unique file and directory names for payloads, such as <code>TMP_DIR=`mktemp -d -t x</code>.

### S1066 - DarkTortilla

DarkTortilla has used `%HiddenReg%` and `%HiddenKey%` as part of its persistence via the Windows registry.

### S0402 - OSX/Shlayer

OSX/Shlayer has used the <code>mktemp</code> utility to make random and unique filenames for payloads, such as <code>export tmpDir="$(mktemp -d /tmp/XXXXXXXXXXXX)"</code> or <code>mktemp -t Installer</code>.

### S1011 - Tarrask

Tarrask is able to create “hidden” scheduled tasks by deleting the Security Descriptor (`SD`) registry value.

### S0670 - WarzoneRAT

WarzoneRAT can masquerade the Process Environment Block on a compromised host to hide its attempts to elevate privileges through `IFileOperation`.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
