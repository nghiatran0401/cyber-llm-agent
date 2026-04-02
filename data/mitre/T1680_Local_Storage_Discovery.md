# T1680 - Local Storage Discovery

**Tactic:** Discovery
**Platforms:** ESXi, IaaS, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1680

## Description

Adversaries may enumerate local drives, disks, and/or volumes and their attributes like total or free space and volume serial number. This can be done to prepare for ransomware-related encryption, to perform Lateral Movement, or as a precursor to Direct Volume Access. 

On ESXi systems, adversaries may use Hypervisor CLI commands such as `esxcli` to list storage connected to the host as well as `.vmdk` files.

On Windows systems, adversaries can use `wmic logicaldisk get` to find information about local network drives. They can also use `Get-PSDrive` in PowerShell to retrieve drives and may additionally use Windows API functions such as `GetDriveType`.

Linux has commands such as `parted`, `lsblk`, `fdisk`, `lshw`, and `df` that can list information about disk partitions such as size, type, file system types, and free space. The command `diskutil` on MacOS can be used to list disks while `system_profiler SPStorageDataType` can additionally show information such as a volume’s mount path, file system, and the type of drive in the system. 

Infrastructure as a Service (IaaS) cloud providers also have commands for storage discovery such as `describe volume` in AWS, `gcloud compute disks list` in GCP, and `az disk list` in Azure.

## Detection

### Detection Analytics

**Analytic 0536**

Drive enumeration using PowerShell (`Get-PSDrive`), `wmic logicaldisk`, or Win32 API indicative of local volume enumeration by non-admin users or executed outside of baseline system inventory scripts.

**Analytic 0537**

Abnormal use of `lsblk`, `fdisk -l`, `lshw -class disk`, or `parted` by non-admin users or within non-interactive shells suggests suspicious disk enumeration activity.

**Analytic 0538**

Disk enumeration via `diskutil list` or `system_profiler SPStorageDataType` run outside of user login or not associated with system inventory tools

**Analytic 0539**

Use of `esxcli storage` or `vim-cmd vmsvc/getallvms` by unusual sessions or through interactive shells unrelated to administrative maintenance tasks.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0456 - Aria-body

Aria-body has the ability to identify disk information on a compromised host.

### S1087 - AsyncRAT

AsyncRAT can check the disk size through the values obtained with `DeviceInfo.`

### S0438 - Attor

Attor monitors the free disk space on the system.

### S0473 - Avenger

Avenger has the ability to identify the host volume ID.

### S0520 - BLINDINGCAN

BLINDINGCAN has collected disk information, including type and free space available.

### S0638 - Babuk

Babuk can enumerate disk volumes, get disk information, and query service status.

### S0234 - Bandook

Bandook can collect information about the drives available on the system.

### S0239 - Bankshot

Bankshot gathers disk type and disk free space.

### S1070 - Black Basta

Black Basta can enumerate volumes.

### S1068 - BlackCat

BlackCat can enumerate local drives.

### S0564 - BlackMould

BlackMould can enumerate local drives on a compromised host.

### S0137 - CORESHELL

CORESHELL collects the volume serial number from the victim and sends the information to its C2 server.

### S0351 - Cannon

Cannon can gather drive information from the victim's machine.

### S0667 - Chrommme

Chrommme has the ability to list drives.

### S0488 - CrackMapExec

CrackMapExec can enumerate the system drives and associated system name.

### S0115 - Crimson

Crimson contains a command to collect disk drive information.

### S0625 - Cuba

Cuba can enumerate local drives, disk type, and disk free space.

### S0616 - DEATHRANSOM

DEATHRANSOM can enumerate logical drives on a target system.

### S1111 - DarkGate

DarkGate uses the Delphi methods <code>Sysutils::DiskSize</code> and <code>GlobalMemoryStatusEx</code> to collect disk size and physical memory as part of the malware's anti-analysis checks for running in a virtualized environment.

### S0091 - Epic

Epic collects disk space information.

### S0181 - FALLCHILL

FALLCHILL can collect information about installed disks from the victim.

### S0267 - FELIXROOT

FELIXROOT collects the victim’s volume serial number.

### S1044 - FunnyDream

FunnyDream can enumerate all logical drives on a targeted machine.

### S0617 - HELLOKITTY

HELLOKITTY can enumerate logical drives on a target system.

### S0376 - HOPLIGHT

HOPLIGHT has been observed collecting victim machine volume information.

### S0697 - HermeticWiper

HermeticWiper can enumerate physical drives on a targeted host.

### S1027 - Heyoka Backdoor

Heyoka Backdoor can enumerate drives on a compromised host.

### S1139 - INC Ransomware

INC Ransomware can discover and mount hidden drives to encrypt them.

### S0259 - InnaputRAT

InnaputRAT gathers volume drive information.

### S0260 - InvisiMole

InvisiMole can gather information on the mapped drives and system volume serial number.

### S0044 - JHUHUGIT

JHUHUGIT obtains a build identifier as well as victim hard drive information from Windows registry key <code>HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum</code>. Another JHUHUGIT variant gathers the victim storage volume serial number and the storage device name.

### S0271 - KEYMARBLE

KEYMARBLE has the capability to collect information on disk devices.

### S0526 - KGH_SPY

KGH_SPY can collect drive information from a compromised host.

### S0356 - KONNI

KONNI can gather information on connected drives and disk space from the victim’s machine.

### S1075 - KOPILUWAK

KOPILUWAK can discover logical drive information on compromised hosts.

### S0265 - Kazuar

Kazuar gathers information on local drives.

### S0607 - KillDisk

KillDisk retrieves the hard disk name by calling the <code>CreateFileA to \\.\PHYSICALDRIVE0</code> API.

### S0680 - LitePower

LitePower has the ability to list local drives.

### S1199 - LockBit 2.0

LockBit 2.0 can enumerate local drive configuration.

### S1202 - LockBit 3.0

LockBit 3.0 can enumerate local drive configuration.

### S1016 - MacMa

MacMa can collect information about a compromised computer's disk sizes.

### S1060 - Mafalda

Mafalda can enumerate all drives on a compromised host.

### S1244 - Medusa Ransomware

Medusa Ransomware has enumerated logical drives on infected hosts.

### S1026 - Mongall

Mongall can identify drives on compromised hosts.

### S0353 - NOKKI

NOKKI can gather information on drives on the victim’s machine.

### S0630 - Nebulae

Nebulae can discover logical drive information including the drive type, free space, and volume information.

### S1147 - Nightdoor

Nightdoor can collect information about disk drives, their total and free space, and file system type.

### S1100 - Ninja

Ninja can obtain information on physical drives from targeted hosts.

### S0340 - Octopus

Octopus can collect system drive and disk size information.

### S1228 - PUBLOAD

PUBLOAD has leveraged `wmic logicaldisk get` to map local network drives.

### S0208 - Pasam

Pasam creates a backdoor through which remote attackers can retrieve information like free disk space.

### S0587 - Penquin

Penquin can report the disk space of a compromised host to C2.

### S0013 - PlugX

PlugX has collected a list of all mapped drives on the infected host.

### S0238 - Proxysvc

Proxysvc collects volume information for all drives on the system.

### S1242 - Qilin

Qilin has used `GetLogicalDrives()` and `EnumResourceW()` to locate mounted drives and shares.

### S0496 - REvil

REvil can identify system drive information on a compromised host.

### S1150 - ROADSWEEP

ROADSWEEP can enumerate logical drives on targeted devices.

### S0458 - Ramsay

Ramsay can detect system information--including disk names, total space, and remaining space--to create a hardware profile GUID which acts as a system identifier for operators.

### S0172 - Reaver

Reaver collects volume serial number from the victim.

### S0448 - Rising Sun

Rising Sun can detect drive information, including drive type, total number of bytes on disk, total number of free bytes on disk, and name of a specified volume.

### S1073 - Royal

Royal can use `GetLogicalDrives` to enumerate logical drives.

### S0253 - RunningRAT

RunningRAT gathers logical drives information and volume information.

### S0446 - Ryuk

Ryuk has called <code>GetLogicalDrives</code> to emumerate all mounted drives, and <code>GetDriveTypeW</code> to determine the drive type.

### S0692 - SILENTTRINITY

SILENTTRINITY can collect information related to a compromised host, including a list of drives.

### S0533 - SLOTHFULMEDIA

SLOTHFULMEDIA has collected disk information from a victim machine.

### S1049 - SUGARUSH

MoonWind can obtain the number of drives on the victim machine.

### S1168 - SampleCheck5000

SampleCheck5000 can create unique victim identifiers by using the compromised system’s volume ID.

### S1085 - Sardonic

Sardonic has the ability to collect the C:\ drive serial number from a compromised machine.

### S0596 - ShadowPad

ShadowPad has discovered system information including volume serial numbers.

### S1089 - SharpDisco

SharpDisco can use a plugin to enumerate system drives.

### S0516 - SoreFang

SoreFang can collect disk space information on victim machines by executing Systeminfo.

### S0491 - StrongPity

StrongPity can identify the hard disk volume serial number on a compromised host.

### S0663 - SysUpdate

SysUpdate can collect a system's drive information.

### S0586 - TAINTEDSCRIBE

TAINTEDSCRIBE can use <code>DriveList</code> to retrieve drive information.

### S1239 - TONESHELL

TONESHELL has retrieved the disk serial number of the device using WMI query `SELECT volumeserialnumber FROM win32_logicaldisk where Name =’C:` to identify the victim machine.

### S0263 - TYPEFRAME

TYPEFRAME can gather the disk volume information.

### S0678 - Torisma

Torisma can use `GetlogicalDrives` to get a bitmask of all drives available on a compromised system. It can also use `GetDriveType` to determine if a new drive is a CD-ROM drive.

### S0689 - WhisperGate

WhisperGate has the ability to enumerate fixed logical drives on a targeted system.

### S1065 - Woody RAT

Woody RAT can retrieve information about storage drives from an infected machine.

### S0251 - Zebrocy

Zebrocy collects the serial number for the storage volume C:\.

### S1151 - ZeroCleare

ZeroCleare can use the `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX`, `IOCTL_DISK_GET_DRIVE_GEOMETRY`, and `IOCTL_DISK_GET_LENGTH_INFO` system calls to compute disk size.

### S0672 - Zox

Zox can enumerate attached drives.

### S0471 - build_downer

build_downer has the ability to send system volume information to C2.

### S0472 - down_new

down_new has the ability to identify the system volume information of a compromised host.

### S1048 - macOS.OSAMiner

macOS.OSAMiner has checked to ensure there is enough disk space using the Unix utility `df`.

### S0248 - yty

yty gathers the the serial number of the main disk volume.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0017 - C0017

During C0017, APT41 issued `ping -n 1 ((cmd /c dir c:\|findstr Number).split()[-1]+` commands to find the volume serial number of compromised systems.

### C0014 - Operation Wocao

During Operation Wocao, threat actors discovered the local disks attached to the system and their hardware information including manufacturer and model.

### C0024 - SolarWinds Compromise

During the SolarWinds Compromise, APT29 used `fsutil` to check available free space before executing actions that might create large files on disk.
