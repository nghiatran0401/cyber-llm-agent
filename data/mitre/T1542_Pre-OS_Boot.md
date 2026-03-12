# T1542 - Pre-OS Boot

**Tactic:** Defense Evasion, Persistence
**Platforms:** Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1542

## Description

Adversaries may abuse Pre-OS Boot mechanisms as a way to establish persistence on a system. During the booting process of a computer, firmware and various startup services are loaded before the operating system. These programs control flow of execution before the operating system takes control.

Adversaries may overwrite data in boot drivers or firmware such as BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) to persist on systems at a layer below the operating system. This can be particularly difficult to detect as malware at this level will not be detected by host software-based defenses.

## Detection

### Detection Analytics

**Analytic 0774**

Unusual modification of boot records (MBR, VBR) or EFI partitions not associated with legitimate patch cycles or OS upgrades. Registry or WMI events associated with firmware update tools executed from unexpected parent processes. API calls (e.g., DeviceIoControl) writing directly to raw disk sectors. Subsequent abnormal boot configuration changes followed by unsigned driver loads.

**Analytic 0775**

Detection of writes to /boot or EFI directories outside of expected package manager updates. Monitoring kernel log and auditd events for attempts to overwrite bootloader binaries (e.g., grub, shim). Unexpected execution of efibootmgr or dd writing to /dev/sdX devices followed by boot parameter changes.

**Analytic 0776**

Abnormal modification of EFI firmware binaries in /System/Library/CoreServices/ or NVRAM parameters not associated with OS updates. Unified logs capturing calls to bless or nvram commands executed from untrusted parent processes. Sudden unsigned kext loads after EFI variable tampering.

**Analytic 0777**

Unexpected firmware image uploads via TFTP/FTP/SCP. Configuration changes modifying boot image pointers. Logs showing boot variable redirection to non-standard images. Anomalous reboots immediately following firmware changes not tied to patch schedules.


## Mitigations

### M1047 - Audit

Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses.

### M1046 - Boot Integrity

Use Trusted Platform Module technology and a secure or trusted boot process to prevent system integrity from being compromised. Check the integrity of the existing BIOS or EFI to determine if it is vulnerable to modification.

### M1035 - Limit Access to Resource Over Network

Prevent access to file shares, remote access to systems, unnecessary services. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc.

### M1026 - Privileged Account Management

Ensure proper permissions are in place to help prevent adversary access to privileged accounts necessary to perform these actions

### M1051 - Update Software

Patch the BIOS and EFI as necessary.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
