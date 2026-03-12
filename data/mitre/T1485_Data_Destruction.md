# T1485 - Data Destruction

**Tactic:** Impact
**Platforms:** Containers, ESXi, IaaS, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1485

## Description

Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources. Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives. Common operating system file deletion commands such as <code>del</code> and <code>rm</code> often only remove pointers to files without wiping the contents of the files themselves, making the files recoverable by proper forensic methodology. This behavior is distinct from Disk Content Wipe and Disk Structure Wipe because individual files are destroyed rather than sections of a storage disk or the disk's logical structure.

Adversaries may attempt to overwrite files and directories with randomly generated data to make it irrecoverable. In some cases politically oriented image files have been used to overwrite data.

To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware designed for destroying data may have worm-like features to propagate across a network by leveraging additional techniques like Valid Accounts, OS Credential Dumping, and SMB/Windows Admin Shares..

In cloud environments, adversaries may leverage access to delete cloud storage objects, machine images, database instances, and other infrastructure crucial to operations to damage an organization or their customers. Similarly, they may delete virtual machines from on-prem virtualized environments.

## Detection

### Detection Analytics

**Analytic 0411**

Adversary spawns command-line tools (e.g., del, cipher /w, SDelete) or scripts to recursively delete or overwrite user/system files. This may be correlated with abnormal file IO activity, registry writes, or tampering in critical system directories.

**Analytic 0412**

Massive recursive deletions or overwrites via `rm -rf`, `shred`, `dd`, or wiper binaries. May include unlink syscalls, deletion of known config/data paths, or sequential overwrite patterns.

**Analytic 0413**

Destruction via `rm -rf`, overwrite with `dd` or `srm`, often executed by script in /tmp or /private/tmp, may also involve file overwrite to political or decoy image data.

**Analytic 0414**

Adversary deletes critical infrastructure: EC2 instances, S3 buckets, snapshots, or volumes using elevated IAM credentials. Frequently includes batch API calls with `Delete*` or `TerminateInstances`.

**Analytic 0415**

Adversary destroys virtual disks (VMDK), images, or VMs by invoking `vim-cmd`, deleting datastore contents, or purging snapshots.

**Analytic 0416**

Container process executes destructive file operations inside volume mounts or host paths. Includes `rm -rf /mnt/volumes/`, container breakout followed by host deletion attempts.


## Mitigations

### M1053 - Data Backup

Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data. Ensure backups are stored off system and protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery.

### M1032 - Multi-factor Authentication

Implement multi-factor authentication (MFA) delete for cloud storage resources, such as AWS S3 buckets, to prevent unauthorized deletion of critical data and infrastructure. MFA delete requires additional authentication steps, making it significantly more difficult for adversaries to destroy data without proper credentials. This additional security layer helps protect against the impact of data destruction in cloud environments by ensuring that only authenticated actions can irreversibly delete storage or machine images.

### M1018 - User Account Management

In cloud environments, limit permissions to modify cloud bucket lifecycle policies (e.g., `PutLifecycleConfiguration` in AWS) to only those accounts that require it. In AWS environments, consider using Service Control policies to limit the use of the `PutBucketLifecycle` API call.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1167 - AcidPour

AcidPour can perform an in-depth wipe of victim filesystems and attached storage devices through either data overwrite or calling various IOCTLS to erase them, similar to AcidRain.

### S1125 - AcidRain

AcidRain performs an in-depth wipe of the target filesystem and various attached storage devices through either a data overwrite or calling various IOCTLS to erase it.

### S1133 - Apostle

Apostle initially masqueraded as ransomware but actual functionality is a data destruction tool, supported by an internal name linked to an early version, <code>wiper-action</code>. Apostle writes random data to original files after an encrypted copy is created, along with resizing the original file to zero and changing time property metadata before finally deleting the original file.

### S0089 - BlackEnergy

BlackEnergy 2 contains a "Destroy" plug-in that destroys data stored on victim hard drives by overwriting file contents.

### S0693 - CaddyWiper

CaddyWiper can work alphabetically through drives on a compromised system to take ownership of and overwrite all files.

### S1134 - DEADWOOD

DEADWOOD overwrites files on victim systems with random data to effectively destroy them.

### S0659 - Diavol

Diavol can delete specified files from a targeted system.

### S0697 - HermeticWiper

HermeticWiper can recursively wipe folders and files in `Windows`, `Program Files`, `Program Files(x86)`, `PerfLogs`, `Boot, System`, `Volume Information`, and `AppData` folders using `FSCTL_MOVE_FILE`. HermeticWiper can also overwrite symbolic links and big files in `My Documents` and on the Desktop with random bytes.

### S0604 - Industroyer

Industroyer’s data wiper module clears registry keys and overwrites both ICS configuration and Windows files.

### S0265 - Kazuar

Kazuar can overwrite files with random data before deleting them.

### S0607 - KillDisk

KillDisk deletes system files to make the OS unbootable. KillDisk also targets and deletes files with 35 different file extensions.

### S0688 - Meteor

Meteor can fill a victim's files and directories with zero-bytes in replacement of real content before deleting them.

### S1135 - MultiLayer Wiper

MultiLayer Wiper deletes files on network drives, but corrupts and overwrites with random data files stored locally.

### S0365 - Olympic Destroyer

Olympic Destroyer overwrites files locally and on remote shares.

### S0139 - PowerDuke

PowerDuke has a command to write random data across a file and delete it.

### S0238 - Proxysvc

Proxysvc can overwrite files indicated by the attacker before deleting them.

### S0496 - REvil

REvil has the capability to destroy files and folders.

### S0364 - RawDisk

RawDisk was used in Shamoon to write to protected system locations such as the MBR and disk partitions in an effort to destroy data.

### S0195 - SDelete

SDelete deletes data in a way that makes it unrecoverable.

### S0140 - Shamoon

Shamoon attempts to overwrite operating system files and disk structures with image files. In a later variant, randomly generated data was used for data overwrites.

### S1178 - ShrinkLocker

ShrinkLocker can initiate a destructive payload depending on the operating system check through resizing and reformatting portions of the victim machine's disk, leading to system instability and potential data corruption.

### S0380 - StoneDrill

StoneDrill has a disk wiper module that targets files other than those in the Windows directory.

### S0689 - WhisperGate

WhisperGate can corrupt files by overwriting the first 1 MB with `0xcc` and appending random extensions.

### S0341 - Xbash

Xbash has destroyed Linux-based databases as part of its ransomware capabilities.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0034 - 2022 Ukraine Electric Power Attack

During the 2022 Ukraine Electric Power Attack, Sandworm Team deployed CaddyWiper on the victim’s IT environment systems to wipe files related to the OT capabilities, along with mapped drives, and physical drive partitions.
