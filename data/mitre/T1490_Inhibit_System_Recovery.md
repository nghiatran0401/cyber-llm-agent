# T1490 - Inhibit System Recovery

**Tactic:** Impact
**Platforms:** Containers, ESXi, IaaS, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1490

## Description

Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery. This may deny access to available backups and recovery options.

Operating systems may contain features that can help fix corrupted systems, such as a backup catalog, volume shadow copies, and automatic repair features. Adversaries may disable or delete system recovery features to augment the effects of Data Destruction and Data Encrypted for Impact. Furthermore, adversaries may disable recovery notifications, then corrupt backups.

A number of native Windows utilities have been used by adversaries to disable or delete system recovery features:

* <code>vssadmin.exe</code> can be used to delete all volume shadow copies on a system - <code>vssadmin.exe delete shadows /all /quiet</code>
* Windows Management Instrumentation can be used to delete volume shadow copies - <code>wmic shadowcopy delete</code>
* <code>wbadmin.exe</code> can be used to delete the Windows Backup Catalog - <code>wbadmin.exe delete catalog -quiet</code>
* <code>bcdedit.exe</code> can be used to disable automatic Windows recovery features by modifying boot configuration data - <code>bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no</code>
* <code>REAgentC.exe</code> can be used to disable Windows Recovery Environment (WinRE) repair/recovery options of an infected system
* <code>diskshadow.exe</code> can be used to delete all volume shadow copies on a system - <code>diskshadow delete shadows all</code>

On network devices, adversaries may leverage Disk Wipe to delete backup firmware images and reformat the file system, then System Shutdown/Reboot to reload the device. Together this activity may leave network devices completely inoperable and inhibit recovery operations.

On ESXi servers, adversaries may delete or encrypt snapshots of virtual machines to support Data Encrypted for Impact, preventing them from being leveraged as backups (e.g., via ` vim-cmd vmsvc/snapshot.removeall`).

Adversaries may also delete “online” backups that are connected to their network – whether via network storage media or through folders that sync to cloud services. In cloud environments, adversaries may disable versioning and backup policies and delete snapshots, database backups, machine images, and prior versions of objects designed to be used in disaster recovery scenarios.

## Detection

### Detection Analytics

**Analytic 0933**

Process chains that use native utilities (vssadmin, wbadmin, diskshadow, bcdedit, REAgentC, wmic) with arguments to delete shadow copies, disable recovery, or remove backup catalogs

**Analytic 0934**

Shell utilities or scripts deleting `/etc/systemd/system/rescue.target`, `/etc/fstab` backups, or `/boot/efi` partitions; chattr used to block snapshot auto-recovery

**Analytic 0935**

ESXi shell or vim-cmd execution that deletes all VM snapshots using vmsvc/snapshot.removeall or rm on snapshot paths

**Analytic 0936**

Execution of `erase`, `format`, and `reload` in immediate sequence from a privileged AAA session

**Analytic 0937**

Cloud API calls disabling snapshot scheduling, backup policies, versioning, followed by DeleteSnapshot/DeleteVolume operations


## Mitigations

### M1053 - Data Backup

Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data. Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery. In cloud environments, enable versioning on storage objects where possible, and copy backups to other accounts or regions to isolate them from the original copies. On ESXi servers, ensure that disk images and snapshots of virtual machines are regularly taken, with copies stored off system.

### M1038 - Execution Prevention

Consider using application control configured to block execution of utilities such as `diskshadow.exe` that may not be required for a given system or network to prevent potential misuse by adversaries.

### M1028 - Operating System Configuration

Consider technical controls to prevent the disabling of services or deletion of files involved in system recovery. Additionally, ensure that WinRE is enabled using the following command: <code>reagentc /enable</code>.

### M1018 - User Account Management

Limit the user accounts that have access to backups to only those required. In AWS environments, consider using Service Control Policies to restrict API calls to delete backups, snapshots, and images.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1129 - Akira

Akira will delete system volume shadow copies via PowerShell commands.

### S0640 - Avaddon

Avaddon deletes backups and shadow copies using native system tools.

### S1136 - BFG Agonizer

BFG Agonizer wipes the boot sector of infected machines to inhibit system recovery.

### S0638 - Babuk

Babuk has the ability to delete shadow volumes using <code>vssadmin.exe delete shadows /all /quiet</code>.

### S0570 - BitPaymer

BitPaymer attempts to remove the backup shadow files from the host using <code>vssadmin.exe Delete Shadows /All /Quiet</code>.

### S1070 - Black Basta

Black Basta can delete shadow copies using vssadmin.exe.

### S1181 - BlackByte 2.0 Ransomware

BlackByte 2.0 Ransomware modifies volume shadow copies during execution in a way that destroys them on the victim machine.

### S1180 - BlackByte Ransomware

BlackByte Ransomware deletes all volume shadow copies and restore points among other actions to inhibit system recovery following ransomware deployment.

### S1068 - BlackCat

BlackCat can delete shadow copies using `vssadmin.exe delete shadows /all /quiet` and `wmic.exe Shadowcopy Delete`; it can also modify the boot loader using `bcdedit /set {default} recoveryenabled No`.

### S0611 - Clop

Clop can delete the shadow volumes with <code>vssadmin Delete Shadows /all /quiet</code> and can use bcdedit to disable recovery options.

### S0608 - Conficker

Conficker resets system restore points and deletes backup files.

### S0575 - Conti

Conti can delete Windows Volume Shadow Copies using <code>vssadmin</code>.

### S0616 - DEATHRANSOM

DEATHRANSOM can delete volume shadow copies on compromised hosts.

### S1111 - DarkGate

DarkGate can delete system restore points through the command <code>cmd.exe /c vssadmin delete shadows /for=c: /all /quiet”</code>.

### S0673 - DarkWatchman

DarkWatchman can delete shadow volumes using <code>vssadmin.exe</code>.

### S0659 - Diavol

Diavol can delete shadow copies using the `IVssBackupComponents` COM object to call the `DeleteSnapshots` method.

### S0605 - EKANS

EKANS removes backups of Volume Shadow Copies to disable any restoration capabilities.

### S1247 - Embargo

Embargo has cleared files from the recycle bin by invoking `SHEmptyRecycleBinW()` and disabled Windows recovery through `C:\Windows\System32\cmd.exe /q /c bcdedit /set {default} recoveryenabled no`.

### S0618 - FIVEHANDS

FIVEHANDS has the ability to delete volume shadow copies on compromised hosts.

### S0132 - H1N1

H1N1 disable recovery options and deletes shadow copies from the victim.

### S0617 - HELLOKITTY

HELLOKITTY can delete volume shadow copies on compromised hosts.

### S0697 - HermeticWiper

HermeticWiper can disable the VSS service on a compromised host using the service control manager.

### S1139 - INC Ransomware

INC Ransomware can delete volume shadow copy backups from victim machines.

### S0260 - InvisiMole

InvisiMole can can remove all system restore points.

### S0389 - JCry

JCry has been observed deleting shadow copies to ensure that data cannot be restored easily.

### S1199 - LockBit 2.0

LockBit 2.0 has the ability to delete volume shadow copies on targeted hosts.

### S1202 - LockBit 3.0

LockBit 3.0 can delete volume shadow copies.

### S0449 - Maze

Maze has attempted to delete the shadow volumes of infected machines, once before and once after the encryption process.

### S1244 - Medusa Ransomware

Medusa Ransomware has deleted recovery files such as shadow copies using `vssadmin.exe`.

### S0576 - MegaCortex

MegaCortex has deleted volume shadow copies using <code>vssadmin.exe</code>.

### S0688 - Meteor

Meteor can use `bcdedit` to delete different boot identifiers on a compromised host; it can also use `vssadmin.exe delete shadows /all /quiet` and `C:\\Windows\\system32\\wbem\\wmic.exe shadowcopy delete`.

### S1135 - MultiLayer Wiper

MultiLayer Wiper wipes the boot sector of infected systems to inhibit system recovery.

### S0457 - Netwalker

Netwalker can delete the infected system's Shadow Volumes to prevent recovery.

### S0365 - Olympic Destroyer

Olympic Destroyer uses the native Windows utilities <code>vssadmin</code>, <code>wbadmin</code>, and <code>bcdedit</code> to delete and disable operating system recovery features such as the Windows backup catalog and Windows Automatic Repair.

### S1162 - Playcrypt

Playcrypt can use AlphaVSS to delete shadow copies.

### S1058 - Prestige

Prestige can delete the backup catalog from the target system using: `c:\Windows\System32\wbadmin.exe delete catalog -quiet` and can also delete volume shadow copies using: `\Windows\System32\vssadmin.exe delete shadows /all /quiet`.

### S0654 - ProLock

ProLock can use vssadmin.exe to remove volume shadow copies.

### S0583 - Pysa

Pysa has the functionality to delete shadow copies.

### S1242 - Qilin

Qilin can execute `vssadmin.exe delete shadows /all /quiet` to remove volume shadow copies.

### S0496 - REvil

REvil can use vssadmin to delete volume shadow copies and bcdedit to disable recovery features.

### S1150 - ROADSWEEP

ROADSWEEP has the ability to disable `SystemRestore` and Volume Shadow Copies.

### S0481 - Ragnar Locker

Ragnar Locker can delete volume shadow copies using <code>vssadmin delete shadows /all /quiet</code>.

### S1212 - RansomHub

RansomHub has used `vssadmin.exe` to delete volume shadow copies.

### S0400 - RobbinHood

RobbinHood deletes shadow copies to ensure that all the data cannot be restored easily.

### S1073 - Royal

Royal can delete shadow copy backups with vssadmin.exe using the command `delete shadows /all /quiet`.

### S0446 - Ryuk

Ryuk has used <code>vssadmin Delete Shadows /all /quiet</code> to to delete volume shadow copies and <code>vssadmin resize shadowstorage</code> to force deletion of shadow copies created by third-party applications.

### S0366 - WannaCry

WannaCry uses <code>vssadmin</code>, <code>wbadmin</code>, <code>bcdedit</code>, and <code>wmic</code> to delete and disable operating system recovery features.

### S0612 - WastedLocker

WastedLocker can delete shadow volumes.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
