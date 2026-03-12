# T1006 - Direct Volume Access

**Tactic:** Defense Evasion
**Platforms:** Network Devices, Windows
**Reference:** https://attack.mitre.org/techniques/T1006

## Description

Adversaries may directly access a volume to bypass file access controls and file system monitoring. Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write files directly from the drive by analyzing file system data structures. This technique may bypass Windows file access controls as well as file system monitoring tools.

Utilities, such as `NinjaCopy`, exist to perform these actions in PowerShell. Adversaries may also use built-in or third-party utilities (such as `vssadmin`, `wbadmin`, and esentutl) to create shadow copies or backups of data from system volumes.

## Detection

### Detection Analytics

**Analytic 1193**

Processes accessing raw logical drives (e.g., \.\C:) to bypass file system protections or directly manipulate data structures.

**Analytic 1194**

CLI or automated utilities accessing raw device volumes or flash storage directly (e.g., via `copy flash:`, `format`, or `partition` commands).


## Mitigations

### M1040 - Behavior Prevention on Endpoint

Some endpoint security solutions can be configured to block some types of behaviors related to efforts by an adversary to create backups, such as command execution or preventing API calls to backup related services.

### M1018 - User Account Management

Ensure only accounts required to configure and manage backups have the privileges to do so. Monitor these accounts for unauthorized backup activity.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0404 - esentutl

esentutl can use the Volume Shadow Copy service to copy locked files such as `ntds.dit`.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0051 - APT28 Nearest Neighbor Campaign

During APT28 Nearest Neighbor Campaign, APT28 accessed volume shadow copies through executing <code>vssadmin</code> in order to dump the NTDS.dit file.
