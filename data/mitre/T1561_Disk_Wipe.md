# T1561 - Disk Wipe

**Tactic:** Impact
**Platforms:** Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1561

## Description

Adversaries may wipe or corrupt raw disk data on specific systems or in large numbers in a network to interrupt availability to system and network resources. With direct write access to a disk, adversaries may attempt to overwrite portions of disk data. Adversaries may opt to wipe arbitrary portions of disk data and/or wipe disk structures like the master boot record (MBR). A complete wipe of all disk sectors may be attempted.

To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware used for wiping disks may have worm-like features to propagate across a network by leveraging additional techniques like Valid Accounts, OS Credential Dumping, and SMB/Windows Admin Shares.

On network devices, adversaries may wipe configuration files and other data from the device using Network Device CLI commands such as `erase`.

## Detection

### Detection Analytics

**Analytic 0384**

Unusual direct disk access attempts (e.g., use of \\.\PhysicalDrive notation), abnormal writes to MBR/boot sectors, and installation of kernel drivers that grant raw disk access. Correlate anomalous process creation with disk modification attempts and driver loads.

**Analytic 0385**

Processes invoking destructive commands (dd, shred, wipe) with raw device targets (e.g., /dev/sda, /dev/nvme0n1). Detect direct writes to disk partitions and abnormal superblock or bootloader modifications. Correlate shell execution with subsequent block device I/O.

**Analytic 0386**

Abnormal invocation of diskutil, asr, or low-level APIs (IOKit) to erase/partition drives. Correlate process execution with unified log entries showing destructive disk operations.

**Analytic 0387**

Execution of destructive CLI commands such as 'erase startup-config', 'erase flash:' or 'format disk' on routers/switches. Detect privilege level escalation preceding destructive commands.


## Mitigations

### M1053 - Data Backup

Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data. Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
