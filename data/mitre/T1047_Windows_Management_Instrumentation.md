# T1047 - Windows Management Instrumentation

**Tactic:** Execution
**Platforms:** Windows
**Reference:** https://attack.mitre.org/techniques/T1047

## Description

Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads. WMI is designed for programmers and is the infrastructure for management data and operations on Windows systems. WMI is an administration feature that provides a uniform environment to access Windows system components.

The WMI service enables both local and remote access, though the latter is facilitated by Remote Services such as Distributed Component Object Model and Windows Remote Management. Remote WMI over DCOM operates using port 135, whereas WMI over WinRM operates over port 5985 when using HTTP and 5986 for HTTPS.

An adversary can use WMI to interact with local and remote systems and use it as a means to execute various behaviors, such as gathering information for Discovery as well as Execution of commands and payloads. For example, `wmic.exe` can be abused by an adversary to delete shadow copies with the command `wmic.exe Shadowcopy Delete` (i.e., Inhibit System Recovery).

**Note:** `wmic.exe` is deprecated as of January of 2024, with the WMIC feature being “disabled by default” on Windows 11+. WMIC will be removed from subsequent Windows releases and replaced by PowerShell as the primary WMI interface. In addition to PowerShell and tools like `wbemtool.exe`, COM APIs can also be used to programmatically interact with WMI via C++, .NET, VBScript, etc.

## Detection

### Detection Analytics

**Analytic 1031**

Detects adversarial abuse of WMI to execute local or remote commands via WMIC, PowerShell, or COM API through a multi-event chain: process creation, command execution, and corresponding network connection if remote.


## Mitigations

### M1040 - Behavior Prevention on Endpoint

On Windows 10, enable Attack Surface Reduction (ASR) rules to block processes created by WMI commands from running. Note: many legitimate tools and applications utilize WMI for command execution.

### M1038 - Execution Prevention

Use application control configured to block execution of <code>wmic.exe</code> if it is not required for a given system or network to prevent potential misuse by adversaries. For example, in Windows 10 and Windows Server 2016 and above, Windows Defender Application Control (WDAC) policy rules may be applied to block the <code>wmic.exe</code> application and to prevent abuse.

### M1026 - Privileged Account Management

Prevent credential overlap across systems of administrator and privileged accounts.

### M1018 - User Account Management

By default, only administrators are allowed to connect remotely using WMI. Restrict other users who are allowed to connect, or disallow all users to connect remotely to WMI.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1028 - Action RAT

Action RAT can use WMI to gather AV products installed on an infected host.

### S0331 - Agent Tesla

Agent Tesla has used wmi queries to gather information from the system.

### S1129 - Akira

Akira will leverage COM objects accessed through WMI during execution to evade detection.

### S0373 - Astaroth

Astaroth uses WMIC to execute payloads.

### S0640 - Avaddon

Avaddon uses wmic.exe to delete shadow copies.

### S1081 - BADHATCH

BADHATCH can utilize WMI to collect system information, create new processes, and run malicious PowerShell scripts on a compromised machine.

### S0534 - Bazar

Bazar can execute a WMI query to gather information about the installed antivirus engine.

### S1070 - Black Basta

Black Basta has used WMI to execute files over the network.

### S1068 - BlackCat

BlackCat can use `wmic.exe` to delete shadow copies on compromised networks.

### S0089 - BlackEnergy

A BlackEnergy 2 plug-in uses WMI to gather victim host details.

### S1063 - Brute Ratel C4

Brute Ratel C4 can use WMI to move laterally.

### S1039 - Bumblebee

Bumblebee can use WMI to gather system information and to spawn processes for code injection.

### S0674 - CharmPower

CharmPower can use `wmic` to gather information from a system.

### S0154 - Cobalt Strike

Cobalt Strike can use WMI to deliver a payload to a remote host.

### S1155 - Covenant

Covenant can utilize WMI to install new Grunt listeners through XSL files or command one-liners.

### S0488 - CrackMapExec

CrackMapExec can execute remote commands using Windows Management Instrumentation.

### S0616 - DEATHRANSOM

DEATHRANSOM has the ability to use WMI to delete volume shadow copies.

### S1111 - DarkGate

DarkGate has used WMI to execute files over the network and to obtain information about the domain.

### S1066 - DarkTortilla

DarkTortilla can use WMI queries to obtain system information.

### S0673 - DarkWatchman

DarkWatchman can use WMI to execute commands.

### S0062 - DustySky

The DustySky dropper uses Windows Management Instrumentation to extract information about the operating system and whether an anti-virus is active.

### S0605 - EKANS

EKANS can use Windows Mangement Instrumentation (WMI) calls to execute operations.

### S0568 - EVILNUM

EVILNUM has used the Windows Management Instrumentation (WMI) tool to enumerate infected machines.

### S0367 - Emotet

Emotet has used WMI to execute powershell.exe.

### S0363 - Empire

Empire can use WMI to deliver a payload to a remote host.

### S0396 - EvilBunny

EvilBunny has used WMI to gather information about the system.

### S0267 - FELIXROOT

FELIXROOT uses WMI to query the Windows Registry.

### S0618 - FIVEHANDS

FIVEHANDS can use WMI to delete files on a  target machine.

### S0381 - FlawedAmmyy

FlawedAmmyy leverages WMI to enumerate anti-virus on the victim.

### S1044 - FunnyDream

FunnyDream can use WMI to open a Windows command shell on a remote machine.

### S0237 - GravityRAT

GravityRAT collects various information via WMI requests, including CPU information in the Win32_Processor entry (Processor ID, Name, Manufacturer and the clock speed).

### S0151 - HALFBAKED

HALFBAKED can use WMI queries to gather system information.

### S0617 - HELLOKITTY

HELLOKITTY can use WMI to delete volume shadow copies.

### S0376 - HOPLIGHT

HOPLIGHT has used WMI to recompile the Managed Object Format (MOF) files in the WMI repository.

### S0698 - HermeticWizard

HermeticWizard can use WMI to create a new process on a remote machine via `C:\windows\system32\cmd.exe /c start C:\windows\system32\\regsvr32.exe /s /iC:\windows\<filename>.dll`.

### S1152 - IMAPLoader

IMAPLoader uses WMI queries to query system information on victim hosts.

### S1139 - INC Ransomware

INC Ransomware has the ability to use wmic.exe to spread to multiple endpoints within a compromised environment.

### S0483 - IcedID

IcedID has used WMI to execute binaries.

### S0357 - Impacket

Impacket's `wmiexec` module can be used to execute commands through WMI.

### S0156 - KOMPROGO

KOMPROGO is capable of running WMI queries.

### S0265 - Kazuar

Kazuar obtains a list of running processes through WMI querying.

### S0250 - Koadic

Koadic can use WMI to execute commands.

### S1160 - Latrodectus

Latrodectus has used WMI in malicious email infection chains to facilitate the installation of remotely-hosted files.

### S1199 - LockBit 2.0

LockBit 2.0 can use wmic.exe to delete volume shadow copies.

### S0532 - Lucifer

Lucifer can use WMI to log into remote machines for propagation.

### S1141 - LunarWeb

LunarWeb can use WMI queries for discovery on the victim host.

### S0449 - Maze

Maze has used WMI to attempt to delete the shadow volumes on a machine, and to connect a virtual machine to the network domain of the victim organization's network.

### S0688 - Meteor

Meteor can use `wmic.exe` as part of its effort to delete shadow copies.

### S0339 - Micropsia

Micropsia searches for anti-virus software and firewall products installed on the victim’s machine using WMI.

### S0553 - MoleNet

MoleNet can perform WMI commands on the system.

### S0256 - Mosquito

Mosquito's installer uses WMI to search for antivirus display names.

### S0457 - Netwalker

Netwalker can use WMI to delete Shadow Volumes.

### S0368 - NotPetya

NotPetya can use <code>wmic</code> to help propagate itself across a network.

### S0340 - Octopus

Octopus has used wmic.exe for local discovery information.

### S0365 - Olympic Destroyer

Olympic Destroyer uses WMI to help propagate itself across a network.

### S0264 - OopsIE

OopsIE uses WMI to perform discovery techniques.

### S0223 - POWERSTATS

POWERSTATS can use WMI queries to retrieve data from compromised hosts.

### S0184 - POWRUNER

POWRUNER may use WMI when collecting information about a victim.

### S1228 - PUBLOAD

PUBLOAD has used `wmic` to gather information from the victim device.

### S0378 - PoshC2

PoshC2 has a number of modules that use WMI to execute tasks.

### S0194 - PowerSploit

PowerSploit's <code>Invoke-WmiCommand</code> CodeExecution module uses WMI to execute and retrieve the output from a PowerShell payload.

### S0654 - ProLock

ProLock can use WMIC to execute scripts on targeted hosts.

### S1032 - PyDCrypt

PyDCrypt has attempted to execute with WMIC.

### S0650 - QakBot

QakBot can execute WMI queries to gather information.

### S0241 - RATANKBA

RATANKBA uses WMI to perform process monitoring.

### S0496 - REvil

REvil can use WMI to monitor for and kill specific processes listed in its configuration file.

### S1130 - Raspberry Robin

Raspberry Robin can execute via LNK containing a command to run a legitimate executable, such as wmic.exe, to download a malicious Windows Installer (MSI) package.

### S0375 - Remexi

Remexi executes received commands with wmic.exe (for WMI commands).

### S0270 - RogueRobin

RogueRobin uses various WMI queries to check if the sample is running in a sandbox.

### S0692 - SILENTTRINITY

SILENTTRINITY can use WMI for lateral movement.

### S0559 - SUNBURST

SUNBURST used the WMI query <code>Select * From Win32_SystemDriver</code> to retrieve a driver listing.

### S1064 - SVCReady

SVCReady can use `WMI` queries to detect the presence of a virtual machine environment.

### S1085 - Sardonic

Sardonic can use WMI to execute PowerShell commands on a compromised machine.

### S0546 - SharpStage

SharpStage can use WMI for execution.

### S1178 - ShrinkLocker

ShrinkLocker uses WMI to query information about the victim operating system.

### S0589 - Sibot

Sibot has used WMI to discover network connections and configurations. Sibot has also used the Win32_Process class to execute a malicious DLL.

### S1086 - Snip3

Snip3 can query the WMI class `Win32_ComputerSystem` to gather information.

### S1124 - SocGholish

SocGholish has used WMI calls for script execution and system profiling.

### S0380 - StoneDrill

StoneDrill has used the WMI command-line (WMIC) utility to run tasks.

### S0603 - Stuxnet

Stuxnet used WMI with an <code>explorer.exe</code> token to execute on a remote share.

### S0663 - SysUpdate

SysUpdate can use WMI for execution on a compromised host.

### S1193 - TAMECAT

TAMECAT has used Windows Management Instrumentation (WMI) to query anti-virus products.

### S1239 - TONESHELL

TONESHELL has used WMI queries to gather information from the system.

### S0386 - Ursnif

Ursnif droppers have used WMI classes to execute PowerShell commands.

### S0476 - Valak

Valak can use <code>wmic process call create</code> in a scheduled task to launch plugins and for execution.

### S0366 - WannaCry

WannaCry utilizes <code>wmic</code> to delete shadow copies.

### S0251 - Zebrocy

One variant of Zebrocy uses WMI queries to gather information.

### S0283 - jRAT

jRAT uses WMIC to identify anti-virus products installed on the victim’s machine and to obtain firewall details.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0025 - 2016 Ukraine Electric Power Attack

During the 2016 Ukraine Electric Power Attack, WMI in scripts were used for remote execution and system surveys.

### C0015 - C0015

During C0015, the threat actors used `wmic` and `rundll32` to load Cobalt Strike onto a target host.

### C0018 - C0018

During C0018, the threat actors used WMIC to modify administrative settings on both a local and a remote host, likely as part of the first stages for their lateral movement; they also used WMI Provider Host (`wmiprvse.exe`) to execute a variety of encoded PowerShell scripts using the `DownloadString` method.

### C0027 - C0027

During C0027, Scattered Spider used Windows Management Instrumentation (WMI) to move laterally via Impacket.

### C0001 - Frankenstein

During Frankenstein, the threat actors used WMI queries to check if various security applications were running as well as to determine the operating system version.

### C0007 - FunnyDream

During FunnyDream, the threat actors used `wmiexec.vbs` to run remote commands.

### C0038 - HomeLand Justice

During HomeLand Justice, threat actors used WMI to modify Windows Defender settings.

### C0022 - Operation Dream Job

During Operation Dream Job, Lazarus Group used WMIC to executed a remote XSL script.

### C0014 - Operation Wocao

During Operation Wocao, threat actors has used WMI to execute commands.

### C0058 - SharePoint ToolShell Exploitation

During SharePoint ToolShell Exploitation, threat actors used WMI for execution.

### C0024 - SolarWinds Compromise

During the SolarWinds Compromise, APT29 used WMI for the remote execution of files for lateral movement.
