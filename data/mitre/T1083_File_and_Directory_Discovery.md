# T1083 - File and Directory Discovery

**Tactic:** Discovery
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1083

## Description

Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from File and Directory Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Many command shell utilities can be used to obtain this information. Examples include <code>dir</code>, <code>tree</code>, <code>ls</code>, <code>find</code>, and <code>locate</code>. Custom tools may also be used to gather file and directory information and interact with the Native API. Adversaries may also leverage a Network Device CLI on network devices to gather file and directory information (e.g. <code>dir</code>, <code>show flash</code>, and/or <code>nvram</code>).

Some files and directories may require elevated or specific user permissions to access.

## Detection

### Detection Analytics

**Analytic 1040**

Execution of file enumeration commands (e.g., 'dir', 'tree') from non-standard processes or unusual user contexts, followed by recursive directory traversal or access to sensitive locations.

**Analytic 1041**

Use of file enumeration commands (e.g., 'ls', 'find', 'locate') executed by suspicious users or scripts accessing broad file hierarchies or restricted directories.

**Analytic 1042**

Execution of file or directory discovery commands (e.g., 'ls', 'find') from terminal or script-based tooling, especially outside normal user workflows.

**Analytic 1043**

Execution of esxcli commands to enumerate datastore, configuration files, or directory structures by unauthorized or remote users.

**Analytic 1044**

Execution of file discovery commands (e.g., 'dir', 'show flash', 'nvram:') from CLI interfaces, especially by unauthorized users or from abnormal source IPs.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0066 - 3PARA RAT

3PARA RAT has a command to retrieve metadata for files on disk as well as a command to list the current working directory.

### S0065 - 4H RAT

4H RAT has the capability to obtain file and directory listings.

### S0045 - ADVSTORESHELL

ADVSTORESHELL can list files and directories.

### S1167 - AcidPour

AcidPour can identify specific files and directories within the Linux operating system corresponding with storage devices for follow-on wiping activity, similar to AcidRain.

### S1125 - AcidRain

AcidRain identifies specific files and directories in the Linux operating system associated with storage devices.

### S1028 - Action RAT

Action RAT has the ability to collect drive and file information on an infected machine.

### S1129 - Akira

Akira examines files prior to encryption to determine if they meet requirements for encryption and can be encrypted by the ransomware. These checks are performed through native Windows functions such as <code>GetFileAttributesW</code>.

### S1194 - Akira _v2

Akira _v2 can target specific files and folders for encryption.

### S1025 - Amadey

Amadey has searched for folders associated with antivirus software.

### S0622 - AppleSeed

AppleSeed has the ability to search for .txt, .ppt, .hwp, .pdf, and .doc files in specified directories.

### S0456 - Aria-body

Aria-body has the ability to gather metadata from a file and to search for file and directory names.

### S0438 - Attor

Attor has a plugin that enumerates files with specific extensions on all hard disk drives and stores file information in encrypted log files.

### S0347 - AuditCred

AuditCred can search through folders and files on the system.

### S0129 - AutoIt backdoor

AutoIt backdoor is capable of identifying documents on the victim with the following extensions: .doc; .pdf, .csv, .ppt, .docx, .pst, .xls, .xlsx, .pptx, and .jpeg.

### S0640 - Avaddon

Avaddon has searched for specific files prior to encryption.

### S0473 - Avenger

Avenger has the ability to browse files in directories such as Program Files and the Desktop.

### S1053 - AvosLocker

AvosLocker has searched for files and directories on a compromised network.

### S0344 - Azorult

Azorult can recursively search for files in folders and collects files from the desktop with certain extensions.

### S0031 - BACKSPACE

BACKSPACE allows adversaries to search for files.

### S0642 - BADFLICK

BADFLICK has searched for files on the infected host.

### S0128 - BADNEWS

BADNEWS identifies files with certain extensions from USB devices, then copies them to a predefined directory.

### S0127 - BBSRAT

BBSRAT can list file and directory information.

### S0069 - BLACKCOFFEE

BLACKCOFFEE has the capability to enumerate files.

### S0520 - BLINDINGCAN

BLINDINGCAN can search, read, write, move, and execute files.

### S0657 - BLUELIGHT

BLUELIGHT can enumerate files and collect associated metadata.

### S1184 - BOLDMOVE

BOLDMOVE can list information of all files in the system recursively from the root directory or from a specified directory.

### S0638 - Babuk

Babuk has the ability to enumerate files on a targeted system.

### S0414 - BabyShark

BabyShark has used <code>dir</code> to search for "programfiles" and "appdata".

### S0475 - BackConfig

BackConfig has the ability to identify folders and files related to previous infections.

### S0093 - Backdoor.Oldrea

Backdoor.Oldrea collects information about available drives, default browser, desktop file list, My Documents, Internet history, program files, and root of available drives. It also searches for ICS-related software files.

### S0337 - BadPatch

BadPatch searches for files with specific file extensions.

### S0234 - Bandook

Bandook has a command to list files on a system.

### S0239 - Bankshot

Bankshot searches for files on the victim's machine.

### S0534 - Bazar

Bazar can enumerate the victim's desktop.

### S1246 - BeaverTail

BeaverTail has searched for .ldb and .log files stored in browser extension directories for collection and exfiltration.

### S0268 - Bisonal

Bisonal can retrieve a file listing from the system.

### S1070 - Black Basta

Black Basta can enumerate specific files for encryption.

### S1068 - BlackCat

BlackCat can enumerate files for encryption.

### S0089 - BlackEnergy

BlackEnergy gathers a list of installed apps from the uninstall program Registry. It also gathers registered mail, browser, and instant messaging clients from the Registry. BlackEnergy has searched for given file types.

### S0564 - BlackMould

BlackMould has the ability to find files on the targeted system.

### S0635 - BoomBox

BoomBox can search for specific files and directories on a machine.

### S0651 - BoxCaon

BoxCaon has searched for files on the system, such as documents located in the desktop folder.

### S0252 - Brave Prince

Brave Prince gathers file and directory information from the victim’s machine.

### S1149 - CHIMNEYSWEEP

CHIMNEYSWEEP has the ability to enumerate directories for files that match a set list.

### S0023 - CHOPSTICK

An older version of CHOPSTICK has a module that monitors all mounted volumes for files with the extensions .doc, .docx, .pgp, .gpg, .m2f, or .m2o.

### S1105 - COATHANGER

COATHANGER will survey the contents of system files during installation.

### S0212 - CORALDECK

CORALDECK searches for specified files.

### S0693 - CaddyWiper

CaddyWiper can enumerate all files and directories on a compromised host.

### S0351 - Cannon

Cannon can obtain victim drive information as well as a list of folders in C:\Program Files.

### S0348 - Cardinal RAT

Cardinal RAT checks its current working directory upon execution and also contains watchdog functionality that ensures its executable is located in the correct path (else it will rewrite the payload).

### S0572 - Caterpillar WebShell

Caterpillar WebShell can search for files in directories.

### S0144 - ChChes

ChChes collects the victim's %TEMP% directory path and version of Internet Explorer.

### S0674 - CharmPower

CharmPower can enumerate drives and list the contents of the C: drive on a victim's computer.

### S1096 - Cheerscrypt

Cheerscrypt can search for log and VMware-related files with .log, .vmdk, .vmem, .vswp, and .vmsn extensions.

### S0020 - China Chopper

China Chopper's server component can list directory contents.

### S0660 - Clambling

Clambling can browse directories on a compromised host.

### S0611 - Clop

Clop has searched folders and subfolders for files to encrypt.

### S0154 - Cobalt Strike

Cobalt Strike can explore files on a compromised system.

### S0575 - Conti

Conti can discover files on a local system.

### S0492 - CookieMiner

CookieMiner has looked for files in the user's home directory with "wallet" in their name using <code>find</code>.

### S0050 - CosmicDuke

CosmicDuke searches attached and mounted drives for file extensions and keywords that match a predefined list.

### S0488 - CrackMapExec

CrackMapExec can discover specified filetypes and log files on a targeted system.

### S1023 - CreepyDrive

CreepyDrive can specify the local file path to upload files from.

### S0115 - Crimson

Crimson contains commands to list files and directories, as well as search for files matching certain extensions from a defined list.

### S0235 - CrossRAT

CrossRAT can list all files on a system.

### S0498 - Cryptoistic

Cryptoistic can scan a directory to identify files for deletion.

### S0625 - Cuba

Cuba can enumerate files by using a variety of functions.

### S1153 - Cuckoo Stealer

Cuckoo Stealer can search for files associated with specific applications.

### S0687 - Cyclops Blink

Cyclops Blink can use the Linux API `statvfs` to enumerate the current working directory.

### S0255 - DDKONG

DDKONG lists files on the victim’s machine.

### S0616 - DEATHRANSOM

DEATHRANSOM can use loop operations to enumerate directories on a compromised host.

### S1159 - DUSTTRAP

DUSTTRAP can enumerate files and directories.

### S0497 - Dacls

Dacls can scan directories on a compromised host.

### S1111 - DarkGate

Some versions of DarkGate search for the hard-coded folder <code>C:\Program Files\e Carte Bleue</code>.

### S0673 - DarkWatchman

DarkWatchman has the ability to enumerate file and folder names.

### S0354 - Denis

Denis has several commands to search directories for files.

### S0021 - Derusbi

Derusbi is capable of obtaining directory, file, and drive listings.

### S0659 - Diavol

Diavol has a command to traverse the files and directories in a given path.

### S0600 - Doki

Doki has resolved the path of a process PID to use as a script argument.

### S0547 - DropBook

DropBook can collect the names of all files and folders in the Program Files directories.

### S0567 - Dtrack

Dtrack can list files on available disk volumes.

### S0062 - DustySky

DustySky scans the victim for files that contain certain keywords and document types including PDF, DOC, DOCX, XLS, and XLSX, from a list that is obtained from the C2 as a text file. It can also identify logical drives for the infected machine.

### S0064 - ELMER

ELMER is capable of performing directory listings.

### S0081 - Elise

A variant of Elise executes <code>dir C:\progra~1</code> when initially run.

### S1247 - Embargo

Embargo has searched for folders, subfolders and other networked or mounted drives for follow on encryption actions. Embargo has also iterated device volumes using `FindFirstVolumeW()` and `FindNextVolumeW()` functions and then calls the `GetVolumePathNamesForVolumeNameW()` function to retrieve a list of drive letters and mounted folder paths for each specified volume.

### S0363 - Empire

Empire includes various modules for finding files of interest on hosts and network shares.

### S0091 - Epic

Epic recursively searches for all .doc files on the system and collects a directory listing of the Desktop, %TEMP%, and %WINDOWS%\Temp directories.

### S1179 - Exbyte

Exbyte enumerates all document files on an infected machine, then creates a summary of these items including filename and directory location prior to exfiltration to cloud hosting services.

### S0181 - FALLCHILL

FALLCHILL can search files on a victim.

### S0618 - FIVEHANDS

FIVEHANDS has the ability to enumerate files on a compromised host in order to encrypt files with specific extensions.

### S0036 - FLASHFLOOD

FLASHFLOOD searches for interesting files (either a default or customized set of file extensions) on the local system and removable media.

### S0628 - FYAnti

FYAnti can search the <code>C:\Windows\Microsoft.NET\</code> directory for files of a specified size.

### S0512 - FatDuke

FatDuke can enumerate directories on target machines.

### S0182 - FinFisher

FinFisher enumerates directories and scans for certain files.

### S0661 - FoggyWeb

FoggyWeb's loader can check for the FoggyWeb backdoor .pri file on a compromised AD FS server.

### S0193 - Forfiles

Forfiles can be used to locate certain types of files/directories in a system.(ex: locate all files with a specific extension, name, and/or age)

### S0277 - FruitFly

FruitFly looks for specific files and file types.

### S1044 - FunnyDream

FunnyDream can identify files with .doc, .docx, .ppt, .pptx, .xls, .xlsx, and .pdf extensions and specific timestamps for collection.

### S0410 - Fysbis

Fysbis has the ability to search for files.

### S0666 - Gelsemium

Gelsemium can retrieve data from specific Windows directories, as well as open random files as part of Virtualization/Sandbox Evasion.

### S0049 - GeminiDuke

GeminiDuke collects information from the victim, including installed drivers, programs previously executed by users, programs and services configured to automatically run at startup, files and folders present in any user's home folder, files and folders present in any user's My Documents, programs installed to the Program Files folder, and recently accessed files, folders, and programs.

### S0249 - Gold Dragon

Gold Dragon lists the directories for Desktop, program files, and the user’s recently accessed files.

### S0493 - GoldenSpy

GoldenSpy has included a program "ExeProtector", which monitors for the existence of GoldenSpy on the infected system and redownloads if necessary.

### S1198 - Gomir

Gomir collects information about directory and file structures, including total number of subdirectories, total number of files, and total size of files on infected systems.

### S0237 - GravityRAT

GravityRAT collects the volumes mapped on the system, and also steals files with the following extensions: .docx, .doc, .pptx, .ppt, .xlsx, .xls, .rtf, and .pdf.

### S0632 - GrimAgent

GrimAgent has the ability to enumerate files and directories on a compromised host.

### S0376 - HOPLIGHT

HOPLIGHT has been observed enumerating system drives and partitions.

### S0070 - HTTPBrowser

HTTPBrowser is capable of listing files, folders, and drives on a victim.

### S1229 - Havoc

The Havoc interface can display a file explorer view of the compromised host.

### S0697 - HermeticWiper

HermeticWiper can enumerate common folders such as My Documents, Desktop, and AppData.

### S1027 - Heyoka Backdoor

Heyoka Backdoor has the ability to search the compromised host for files.

### S0431 - HotCroissant

HotCroissant has the ability to retrieve a list of files in a given directory as well as drives and drive types.

### S0203 - Hydraq

Hydraq creates a backdoor through which remote attackers can check for the existence of files, including its own components, as well as retrieve a list of logical drives.

### S1139 - INC Ransomware

INC Ransomware can receive command line arguments to encrypt specific files and directories.

### S1022 - IceApple

The IceApple Directory Lister module can list information about files and directories including creation time, last write time, name, and size.

### S0434 - Imminent Monitor

Imminent Monitor has a dynamic debugging feature to check whether it is located in the %TEMP% directory, otherwise it copies itself there.

### S0604 - Industroyer

Industroyer’s data wiper component enumerates specific files on all the Windows drives.

### S0259 - InnaputRAT

InnaputRAT enumerates directories and obtains file attributes on a system.

### S0260 - InvisiMole

InvisiMole can list information about files in a directory and recently opened or used documents. InvisiMole can also search for specific files by supplied file mask.

### S1245 - InvisibleFerret

InvisibleFerret has identified specific directories and files for exfiltration using the `ssh_upload` command which contains subcommands of `.sdira`, `sdir`, `sfile`, `sfinda`, `sfindr`, `sfind`. InvisibleFerret also has the capability to scan and upload files of interest from multiple OS systems through the use of scripts that check file names, file extensions, and avoids certain path names. InvisibleFerret has utilized the `findstr` on Windows or the macOS `find` commands to search for files of interest.

### S0015 - Ixeshe

Ixeshe can list file and directory information.

### S0201 - JPIN

JPIN can enumerate drives and their types. It can also change file permissions using cacls.exe.

### S0271 - KEYMARBLE

KEYMARBLE has a command to search for files on the victim’s machine.

### S0526 - KGH_SPY

KGH_SPY can enumerate files and directories on a compromised host.

### S0356 - KONNI

A version of KONNI searches for filenames created with a previous version of the malware, suggesting different versions targeted the same victims and the versions may work together.

### S0088 - Kasidet

Kasidet has the ability to search for a given filename on a victim.

### S0265 - Kazuar

Kazuar finds a specified directory, lists the files and metadata about those files.

### S0387 - KeyBoy

KeyBoy has a command to launch a file browser or explorer on the system.

### S0607 - KillDisk

KillDisk has used the <code>FindNextFile</code> command as part of its file deletion process.

### S0599 - Kinsing

Kinsing has used the find command to search for specific files.

### S0437 - Kivars

Kivars has the ability to list drives on the infected host.

### S0250 - Koadic

Koadic can obtain a list of directories.

### S0236 - Kwampirs

Kwampirs collects a list of files and directories in C:\ with the command <code>dir /s /a c:\ >> "C:\windows\TEMP\[RANDOM].tmp"</code>.

### S1121 - LITTLELAMB.WOOLTEA

LITTLELAMB.WOOLTEA can monitor for system upgrade events by checking for the presence of `/tmp/data/root/dev`.

### S1160 - Latrodectus

Latrodectus can collect desktop filenames.

### S1185 - LightSpy

LightSpy uses the `NSFileManager` to move, create and delete files. LightSpy can also use the assembly `bt` instruction to determine a file's executable permissions.

### S0211 - Linfo

Linfo creates a backdoor through which remote attackers can list contents of drives and search for files.

### S1101 - LoFiSe

LoFiSe can monitor the file system to identify files less than 6.4 MB in size with file extensions including .doc, .docx, .xls, .xlsx, .ppt, .pptx, .pdf, .rtf, .tif, .odt, .ods, .odp, .eml, and .msg.

### S1199 - LockBit 2.0

LockBit 2.0 can exclude files associated with core system functions from encryption.

### S1202 - LockBit 3.0

LockBit 3.0 can exclude files associated with core system functions from encryption.

### S0447 - Lokibot

Lokibot can search for specific files on an infected host.

### S0582 - LookBack

LookBack can retrieve file listings from the victim machine.

### S1142 - LunarMail

LunarMail can search its staging directory for output files it has produced.

### S1141 - LunarWeb

LunarWeb has the ability to retrieve directory listings.

### S0443 - MESSAGETAP

MESSAGETAP checks for the existence of two configuration files (keyword_parm.txt and parm.txt) and attempts to read the files every 30 seconds.

### S1016 - MacMa

MacMa can search for a specific file on the compromised computer and can enumerate files in Desktop, Downloads, and Documents folders.

### S0409 - Machete

Machete produces file listings in order to search for files to be exfiltrated.

### S1060 - Mafalda

Mafalda can search for files and directories.

### S1169 - Mango

Mango can enumerate the contents of current working or other specified directories.

### S1156 - Manjusaka

Manjusaka can gather information about specific files on the victim system.

### S0652 - MarkiRAT

MarkiRAT can look for files carrying specific extensions such as: .rtf, .doc, .docx, .xls, .xlsx, .ppt, .pptx, .pps, .ppsx, .txt, .gpg, .pkr, .kdbx, .key, and .jpb.

### S1244 - Medusa Ransomware

Medusa Ransomware has searched for files within the victim environment for encryption and exfiltration.  Medusa Ransomware has also identified files associated with remote management services.

### S0576 - MegaCortex

MegaCortex can parse the available drives and directories to determine which files to encrypt.

### S1191 - Megazord

Megazord can ignore specified directories for encryption.

### S0455 - Metamorfo

Metamorfo has searched the Program Files directories for specific folders and has searched for strings related to its mutexes.

### S0339 - Micropsia

Micropsia can perform a recursive directory listing for all volume drives available on the victim's machine and can also fetch specific files by their paths.

### S0051 - MiniDuke

MiniDuke can enumerate local drives.

### S0083 - Misdat

Misdat is capable of running commands to obtain a list of files and directories, as well as enumerating logical drives.

### S1122 - Mispadu

Mispadu searches for various filesystem paths to determine what banking applications are installed on the victim’s machine.

### S0079 - MobileOrder

MobileOrder has a command to upload to its C2 server information about files on the victim mobile device, including SD card size, installed app list, SMS content, contacts, and calling history.

### S0149 - MoonWind

MoonWind has a command to return a directory listing for a specified directory.

### S1135 - MultiLayer Wiper

MultiLayer Wiper generates a list of all files and paths on the fixed drives of an infected system, enumerating all files on the system except specific folders defined in a hardcoded list.

### S0272 - NDiskMonitor

NDiskMonitor can obtain a list of all files and directories as well as logical drives.

### S0034 - NETEAGLE

NETEAGLE allows adversaries to enumerate and modify the infected host's file system. It supports searching for directories, creating directories, listing directory contents, reading and writing to files, retrieving file attributes, and retrieving volume information.

### S0198 - NETWIRE

NETWIRE has the ability to search for files on the compromised host.

### S0630 - Nebulae

Nebulae can list files and directories on a compromised host.

### S1090 - NightClub

NightClub can use a file monitor to identify .lnk, .doc, .docx, .xls, .xslx, and .pdf files.

### S1100 - Ninja

Ninja has the ability to enumerate directory content.

### S0368 - NotPetya

NotPetya searches for files ending with dozens of different file extensions prior to encryption.

### S1170 - ODAgent

ODAgent can identify the current working directory.

### S0402 - OSX/Shlayer

OSX/Shlayer has used the command <code>appDir="$(dirname $(dirname "$currentDir"))"</code> and <code>$(dirname "$(pwd -P)")</code> to construct installation paths.

### S0644 - ObliqueRAT

ObliqueRAT has the ability to recursively enumerate files on an infected endpoint.

### S0346 - OceanSalt

OceanSalt can extract drive information from the endpoint and search files on the system.

### S0340 - Octopus

Octopus can collect information on the Windows directory and searches for compressed RAR files on the host.

### S0439 - Okrum

Okrum has used DriveLetterView to enumerate drive information.

### S0229 - Orz

Orz can gather victim drive information.

### S1017 - OutSteel

OutSteel can search for specific file extensions, including zipped files.

### S0072 - OwaAuth

OwaAuth has a command to list its directory and logical drives.

### S0598 - P.A.S. Webshell

P.A.S. Webshell has the ability to list files and file characteristics including extension, size, ownership, and permissions.

### S1109 - PACEMAKER

PACEMAKER can parse `/proc/"process_name"/cmdline` to look for the string `dswsd` within the command line.

### S0435 - PLEAD

PLEAD has the ability to list drives and files on the compromised host.

### S0216 - POORAIM

POORAIM can conduct file browsing.

### S0184 - POWRUNER

POWRUNER may enumerate user directories on a victim.

### S0208 - Pasam

Pasam creates a backdoor through which remote attackers can retrieve lists of files.

### S1102 - Pcexter

Pcexter has the ability to search for files in specified directories.

### S0587 - Penquin

Penquin can use the command code <code>do_vslist</code> to send file names, size, and status to C2.

### S0643 - Peppy

Peppy can identify specific files for exfiltration.

### S0048 - PinchDuke

PinchDuke searches for files created within a certain timeframe and whose file extension matches a predefined list.

### S1031 - PingPull

PingPull can enumerate storage volumes and folder contents of a compromised host.

### S0124 - Pisloader

Pisloader has commands to list drives on the victim machine and to list file information for a given directory.

### S1162 - Playcrypt

Playcrypt can avoid encrypting files with a .PLAY, .exe, .msi, .dll, .lnk, or .sys file extension.

### S0013 - PlugX

PlugX has a module to enumerate drives and find files recursively. PlugX has also checked the path from which it is running for specific parameters prior to execution.

### S0428 - PoetRAT

PoetRAT has the ability to list files upon receiving the <code>ls</code> command from C2.

### S0378 - PoshC2

PoshC2 can enumerate files on the local file system and includes a module for enumerating recently accessed files.

### S0139 - PowerDuke

PowerDuke has commands to get the current directory name as well as the size of a file. It also has commands to obtain information about logical drives, drive type, and free space.

### S1058 - Prestige

Prestige can traverse the file system to discover files to encrypt by identifying specific extensions defined in a hardcoded list.

### S0113 - Prikormka

A module in Prikormka collects information about the paths, size, and creation time of files with specific file extensions, but not the actual content of the file.

### S0238 - Proxysvc

Proxysvc lists files in directories.

### S0078 - Psylo

Psylo has commands to enumerate all storage devices and to find all files that start with a particular string.

### S0147 - Pteranodon

Pteranodon identifies files matching certain file extension and copies them to subdirectories it created.

### S0192 - Pupy

Pupy can walk through directories and recursively search for strings in files.

### S0650 - QakBot

QakBot can identify whether it has been run previously on a host by checking for a specified folder.

### S1242 - Qilin

Qilin can exclude specific directories and files from encryption.

### S0686 - QuietSieve

QuietSieve can search files on the target host by extension, including doc, docx, xls, rtf, odt, txt, jpg, pdf, rar, zip, and 7z.

### S0055 - RARSTONE

RARSTONE obtains installer properties from Uninstall Registry Key entries to obtain information about installed applications and how to uninstall certain applications.

### S0496 - REvil

REvil has the ability to identify specific files and directories that are not to be encrypted.

### S1150 - ROADSWEEP

ROADSWEEP can enumerate files on infected devices and avoid encrypting files with .exe, .dll, 	.sys, .lnk, or . lck extensions.

### S0240 - ROKRAT

ROKRAT has the ability to gather a list of files and directories on the infected system.

### S0148 - RTM

RTM can check for specific files and directories associated with virtualization and malware analysis.

### S1148 - Raccoon Stealer

Raccoon Stealer identifies target files and directories for collection based on a configuration file.

### S0629 - RainyDay

RainyDay can use a file exfiltration tool to collect recently changed files with specific extensions.

### S0458 - Ramsay

Ramsay can collect directory and file lists.

### S1212 - RansomHub

RansomHub has the ability to only encrypt specific files.

### S1130 - Raspberry Robin

Raspberry Robin will check to see if the initial executing script is located on the user's Desktop as an anti-analysis check.

### S1040 - Rclone

Rclone can list files and directories with the `ls`, `lsd`, and `lsl` commands.

### S0153 - RedLeaves

RedLeaves can enumerate and search for files and directories.

### S0332 - Remcos

Remcos can search for files on the infected machine.

### S0375 - Remexi

Remexi searches for files on the system.

### S0592 - RemoteUtilities

RemoteUtilities can enumerate files and directories on a target machine.

### S0125 - Remsec

Remsec is capable of listing contents of folders on the victim. Remsec also searches for custom network encryption software on victims.

### S0448 - Rising Sun

Rising Sun can enumerate information about files from the infected system, including file size, attributes, creation time, last access time, and write time. Rising Sun can enumerate the compilation timestamp of Windows executable files.

### S0090 - Rover

Rover automatically searches for files on local drives based on a predefined list of file extensions.

### S1073 - Royal

Royal can identify specific files and directories to exclude from the encryption process.

### S0446 - Ryuk

Ryuk has enumerated files and folders on all mounted drives.

### S0461 - SDBbot

SDBbot has the ability to get directory listings or drive information on a compromised host.

### S0063 - SHOTPUT

SHOTPUT has a command to obtain a directory listing.

### S0692 - SILENTTRINITY

SILENTTRINITY has several modules, such as `ls.py`, `pwd.py`, and `recentFiles.py`, to enumerate directories and files.

### S0533 - SLOTHFULMEDIA

SLOTHFULMEDIA can enumerate files and directories.

### S0157 - SOUNDBITE

SOUNDBITE is capable of enumerating and manipulating files and directories.

### S0035 - SPACESHIP

SPACESHIP identifies files and directories for collection by searching for specific file extensions or file modification time.

### S1042 - SUGARDUMP

SUGARDUMP can search for and collect data from specific Chrome, Opera, Microsoft Edge, and Firefox files, including any folders that have the string `Profile` in its name.

### S0559 - SUNBURST

SUNBURST had commands to enumerate files and directories.

### S0562 - SUNSPOT

SUNSPOT enumerated the Orion software Visual Studio solution directory path.

### S1018 - Saint Bot

Saint Bot can search a compromised host for specific files.

### S1099 - Samurai

Samurai can use a specific module for file enumeration.

### S0345 - Seasalt

Seasalt has the capability to identify the drive type on a victim.

### S1089 - SharpDisco

SharpDisco can identify recently opened files by using an LNK format parser to extract the original file path from LNK files found in either `%USERPROFILE%\Recent` (Windows XP) or `%APPDATA%\Microsoft\Windows\Recent` (newer Windows versions) .

### S0444 - ShimRat

ShimRat can list directories.

### S0610 - SideTwist

SideTwist has the ability to search for specific files.

### S0623 - Siloscape

Siloscape searches for the Kubernetes config file and other related files using a regular expression.

### S0468 - Skidmap

Skidmap has checked for the existence of specific files including <code>/usr/sbin/setenforce</code> and <code> /etc/selinux/config</code>. It also has the ability to monitor the cryptocurrency miner file and process.

### S0633 - Sliver

Sliver can enumerate files on a target system.

### S0226 - Smoke Loader

Smoke Loader recursively searches through directories for files.

### S0615 - SombRAT

SombRAT can execute <code>enum</code> to enumerate files in storage on a compromised system.

### S0516 - SoreFang

SoreFang has the ability to list directories.

### S1140 - Spica

Spica can list filesystem contents on targeted systems.

### S1234 - SplatCloak

SplatCloak has used Windows API to identify files associated with Windows Defender and Kaspersky.

### S1200 - StealBit

StealBit can be configured to exfiltrate specific file types.

### S0142 - StreamEx

StreamEx has the ability to enumerate drive types.

### S1034 - StrifeWater

StrifeWater can enumerate files on a compromised host.

### S0491 - StrongPity

StrongPity can parse the hard drive on a compromised host to identify specific file extensions.

### S0603 - Stuxnet

Stuxnet uses a driver to scan for specific filesystem driver objects.

### S0242 - SynAck

SynAck checks its directory location in an attempt to avoid launching in a sandbox.

### S0663 - SysUpdate

SysUpdate can search files on a compromised host.

### S0586 - TAINTEDSCRIBE

TAINTEDSCRIBE can use <code>DirectoryList</code> to enumerate files in a specified directory.

### S0131 - TINYTYPHON

TINYTYPHON searches through the drive containing the OS, then all drive letters C through to Z, for documents matching certain extensions.

### S0436 - TSCookie

TSCookie has the ability to discover drive information on the infected host.

### S0263 - TYPEFRAME

TYPEFRAME can search directories for files on the victim’s machine.

### S0011 - Taidoor

Taidoor can search for specific files.

### S0467 - TajMahal

TajMahal has the ability to index files from drives, user profiles, and removable drives.

### S0665 - ThreatNeedle

ThreatNeedle can obtain file and directory information.

### S0266 - TrickBot

TrickBot searches the system for all of the following file extensions: .avi, .mov, .mkv, .mpeg, .mpeg4, .mp4, .mp3, .wav, .ogg, .jpeg, .jpg, .png, .bmp, .gif, .tiff, .ico, .xlsx, and .zip. It can also obtain browsing history, cookies, and plug-in information.

### S0094 - Trojan.Karagany

Trojan.Karagany can enumerate files and directories on a compromised host.

### S1196 - Troll Stealer

Troll Stealer can enumerate and collect items from local drives and folders.

### S0647 - Turian

Turian can search for specific files and list directories.

### S0275 - UPPERCUT

UPPERCUT has the capability to gather the victim's current directory.

### S0136 - USBStealer

USBStealer searches victim drives for files matching certain extensions (“.skr”,“.pkr” or “.key”) or names.

### S0452 - USBferry

USBferry can detect the victim's file or folder list.

### S0022 - Uroburos

Uroburos can search for specific files on a compromised system.

### S0180 - Volgmer

Volgmer can list directories on a victim.

### S0219 - WINERACK

WINERACK can enumerate files and directories.

### S0366 - WannaCry

WannaCry searches for variety of user files by file extension before encrypting them using RSA and AES, including Office, PDF, image, audio, video, source code, archive/compression format, and key and certificate files.

### S0670 - WarzoneRAT

WarzoneRAT can enumerate directories on a compromise host.

### S0612 - WastedLocker

WastedLocker can enumerate files and directories just prior to encryption.

### S0689 - WhisperGate

WhisperGate can locate files based on hardcoded file extensions.

### S0059 - WinMM

WinMM sets a WH_CBT Windows hook to search for and capture files on the victim.

### S0466 - WindTail

WindTail has the ability to enumerate the users home directory and the path to its own application bundle.

### S0141 - Winnti for Windows

Winnti for Windows can check for the presence of specific files prior to moving to the next phase of execution.

### S1065 - Woody RAT

Woody RAT can list all files and their associated attributes, including filename, type, owner, creation time, last access time, last write time, size, and permissions.

### S0161 - XAgentOSX

XAgentOSX contains the readFiles function to return a detailed listing (sometimes recursive) of a specified directory. XAgentOSX contains the showBackupIosFolder function to check for IOS device backups by running <code>ls -la ~/Library/Application\ Support/MobileSync/Backup/</code>.

### S0658 - XCSSET

XCSSET has used `mdfind` to enumerate a list of apps known to grant screen sharing permissions and leverages a module to run the command `ls -la ~/Desktop`.

### S1114 - ZIPLINE

ZIPLINE can find and append specific files on Ivanti Connect Secure VPNs based upon received commands.

### S0086 - ZLib

ZLib has the ability to enumerate files and drives.

### S0251 - Zebrocy

Zebrocy searches for files that are 60mb and less and contain the following extensions: .doc, .docx, .xls, .xlsx, .ppt, .pptx, .exe, .zip, and .rar. Zebrocy also runs the <code>echo %APPDATA%</code> command to list the contents of the directory. Zebrocy can obtain the current execution path as well as perform drive enumeration.

### S0330 - Zeus Panda

Zeus Panda searches for specific directories on the victim’s machine.

### S0672 - Zox

Zox can enumerate files on a compromised host.

### S0412 - ZxShell

ZxShell has a command to open a file manager and explorer on the system.

### S1043 - ccf32

ccf32 can parse collected files to identify specific file extensions.

### S0106 - cmd

cmd can be used to find files and directories with native functionality such as <code>dir</code> commands.

### S0472 - down_new

down_new has the ability to list the directories on a compromised host.

### S0283 - jRAT

jRAT can browse file systems.

### S1059 - metaMain

metaMain can recursively enumerate files in an operator-provided directory.

### S0385 - njRAT

njRAT can browse file systems using a file manager module.

### S0248 - yty

yty gathers information on victim’s drives and has a plugin for document listing.

### S0350 - zwShell

zwShell can browse the file system.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0015 - C0015

During C0015, the threat actors conducted a file listing discovery against multiple hosts to ensure locker encryption was successful.

### C0035 - KV Botnet Activity

KV Botnet Activity gathers a list of filenames from the following locations during execution of the final botnet stage: <code>\/usr\/sbin\/</code>, <code>\/usr\/bin\/</code>,  <code>\/sbin\/</code>, <code>\/pfrm2.0\/bin\/</code>, <code>\/usr\/local\/bin\/</code>.

### C0002 - Night Dragon

During Night Dragon, threat actors used zwShell to establish full remote control of the connected machine and browse the victim file system.

### C0012 - Operation CuckooBees

During Operation CuckooBees, the threat actors used `dir c:\\` to search for files.

### C0022 - Operation Dream Job

During Operation Dream Job, Lazarus Group conducted word searches within documents on a compromised host in search of security and financial matters.

### C0006 - Operation Honeybee

During Operation Honeybee, the threat actors used a malicious DLL to search for files with specific keywords.

### C0014 - Operation Wocao

During Operation Wocao, threat actors gathered a recursive directory listing to find files and directories of interest.

### C0059 - Salesforce Data Exfiltration

During Salesforce Data Exfiltration, threat actors queried customers' Salesforce environments to identify sensitive information for exfiltration.

### C0058 - SharePoint ToolShell Exploitation

During SharePoint ToolShell Exploitation, threat actors leveraged commands to locate accessible file shares, backup paths, or SharePoint content.

### C0024 - SolarWinds Compromise

During the SolarWinds Compromise, APT29 obtained information about the configured Exchange virtual directory using `Get-WebServicesVirtualDirectory`.
