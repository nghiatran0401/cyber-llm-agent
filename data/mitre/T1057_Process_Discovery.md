# T1057 - Process Discovery

**Tactic:** Discovery
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1057

## Description

Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network. Administrator or otherwise elevated access may provide better process details. Adversaries may use the information from Process Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

In Windows environments, adversaries could obtain details on running processes using the Tasklist utility via cmd or <code>Get-Process</code> via PowerShell. Information about processes can also be extracted from the output of Native API calls such as <code>CreateToolhelp32Snapshot</code>. In Mac and Linux, this is accomplished with the <code>ps</code> command. Adversaries may also opt to enumerate processes via `/proc`. ESXi also supports use of the `ps` command, as well as `esxcli system process list`.

On network devices, Network Device CLI commands such as `show processes` can be used to display current running processes.

## Detection

### Detection Analytics

**Analytic 0095**

Identifies adversary behavior that launches commands or invokes APIs to enumerate active processes (e.g., tasklist.exe, Get-Process, or CreateToolhelp32Snapshot). Detects execution combined with parent process lineage, network session context, or remote origin.

**Analytic 0096**

Detects execution of common process enumeration utilities (e.g., ps, top, htop) or access to /proc with suspicious ancestry. Correlates command usage with interactive shell context and user role.

**Analytic 0097**

Monitors execution of ps, top, or launchctl with unusual parent processes or from terminal scripts. Also detects AppleScript-based process listing or `system_profiler SPApplicationsDataType` misuse.

**Analytic 0098**

Detects process enumeration using `esxcli system process list` or `ps` on ESXi shell or via unauthorized SSH sessions. Correlates with interactive sessions and abnormal user roles.

**Analytic 0099**

Monitors CLI-based execution of `show process` or equivalent on routers/switches. Correlates unusual device access, unauthorized roles, or config mode changes.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0065 - 4H RAT

4H RAT has the capability to obtain a listing of running processes (including loaded modules).

### S0045 - ADVSTORESHELL

ADVSTORESHELL can list running processes.

### S0331 - Agent Tesla

Agent Tesla can list the current running processes on the system.

### S1129 - Akira

Akira verifies the deletion of volume shadow copies by checking for the existence of the process ID related to the process created to delete these items.

### S1133 - Apostle

Apostle retrieves a list of all running processes on a victim host, and stops all services containing the string "sql," likely to propagate ransomware activity to database files.

### S0622 - AppleSeed

AppleSeed can enumerate the current process on a compromised host.

### S0456 - Aria-body

Aria-body has the ability to enumerate loaded modules for a process..

### S0373 - Astaroth

Astaroth searches for different processes on the system.

### S1087 - AsyncRAT

AsyncRAT can examine running processes to determine if a debugger is present.

### S0640 - Avaddon

Avaddon has collected information about running processes.

### S0473 - Avenger

Avenger has the ability to use Tasklist to identify running processes.

### S1053 - AvosLocker

AvosLocker has discovered system processes by calling `RmGetList`.

### S0344 - Azorult

Azorult can collect a list of running processes by calling CreateToolhelp32Snapshot.

### S0031 - BACKSPACE

BACKSPACE may collect information about running processes.

### S1081 - BADHATCH

BADHATCH can retrieve a list of running processes from a compromised machine.

### S0127 - BBSRAT

BBSRAT can list running processes.

### S0017 - BISCUIT

BISCUIT has a command to enumerate running processes and identify their owners.

### S0069 - BLACKCOFFEE

BLACKCOFFEE has the capability to discover processes.

### S0657 - BLUELIGHT

BLUELIGHT can collect process filenames and SID authority level.

### S0638 - Babuk

Babuk has the ability to check running processes on a targeted system.

### S0414 - BabyShark

BabyShark has executed the <code>tasklist</code> command.

### S0093 - Backdoor.Oldrea

Backdoor.Oldrea collects information about running processes.

### S0606 - Bad Rabbit

Bad Rabbit can enumerate all running processes to compare hashes.

### S0239 - Bankshot

Bankshot identifies processes and collects the process ids.

### S0534 - Bazar

Bazar can identity the current process on a compromised host.

### S0268 - Bisonal

Bisonal can obtain a list of running processes on the victim’s machine.

### S0089 - BlackEnergy

BlackEnergy has gathered a process list by using Tasklist.exe.

### S0486 - Bonadan

Bonadan can use the <code>ps</code> command to discover other cryptocurrency miners active on the system.

### S0252 - Brave Prince

Brave Prince lists the running processes.

### S1063 - Brute Ratel C4

Brute Ratel C4 can enumerate all processes and locate specific process IDs (PIDs).

### S1039 - Bumblebee

Bumblebee can identify processes associated with analytical tools.

### S0482 - Bundlore

Bundlore has used the <code>ps</code> command to list processes.

### S1149 - CHIMNEYSWEEP

CHIMNEYSWEEP can check if a process name contains “creensaver.”

### S1105 - COATHANGER

COATHANGER will query running process information to determine subsequent program execution flow.

### S0693 - CaddyWiper

CaddyWiper can obtain a list of current processes.

### S0351 - Cannon

Cannon can obtain a list of processes running on the system.

### S0030 - Carbanak

Carbanak lists running processes.

### S0484 - Carberp

Carberp has collected a list of running processes.

### S0335 - Carbon

Carbon can list the processes on the victim’s machine.

### S0348 - Cardinal RAT

Cardinal RAT contains watchdog functionality that ensures its process is always running, else spawns a new instance.

### S0572 - Caterpillar WebShell

Caterpillar WebShell can gather a list of processes running on the machine.

### S0144 - ChChes

ChChes collects its process identifier (PID) on the victim.

### S0674 - CharmPower

CharmPower has the ability to list running processes through the use of `tasklist`.

### S0660 - Clambling

Clambling can enumerate processes on a targeted system.

### S0611 - Clop

Clop can enumerate all processes on the victim's machine.

### S0154 - Cobalt Strike

Cobalt Strike's Beacon payload can collect information on process details.

### S0244 - Comnie

Comnie uses the <code>tasklist</code> to view running processes on the victim’s machine.

### S0575 - Conti

Conti can enumerate through all open processes to search for any that have the string “sql” in their process name.

### S0115 - Crimson

Crimson contains a command to list processes.

### S0625 - Cuba

Cuba can enumerate processes running on a victim's machine.

### S1153 - Cuckoo Stealer

Cuckoo Stealer can use `ps aux` to enumerate running processes.

### S0687 - Cyclops Blink

Cyclops Blink can enumerate the process it is currently running under.

### S0694 - DRATzarus

DRATzarus can enumerate and examine running processes to determine if a debugger is present.

### S1159 - DUSTTRAP

DUSTTRAP can enumerate running processes.

### S0497 - Dacls

Dacls can collect data on running and parent processes.

### S0334 - DarkComet

DarkComet can list active processes running on the victim’s machine.

### S1111 - DarkGate

DarkGate performs various checks for running processes, including security software by looking for hard-coded process name values.

### S1066 - DarkTortilla

DarkTortilla can enumerate a list of running processes on a compromised system.

### S0021 - Derusbi

Derusbi collects current and parent process IDs.

### S0659 - Diavol

Diavol has used `CreateToolhelp32Snapshot`, `Process32First`, and `Process32Next` API calls to enumerate the running processes in the system.

### S0600 - Doki

Doki has searched for the current process’s PID.

### S0695 - Donut

Donut includes subprojects that enumerate and identify information about Process Injection candidates.

### S0567 - Dtrack

Dtrack’s dropper can list all running processes.

### S0038 - Duqu

The discovery modules used with Duqu can collect information on process details.

### S0062 - DustySky

DustySky collects information about running processes from victims.

### S0605 - EKANS

EKANS looks for processes from a hard-coded list.

### S0064 - ELMER

ELMER is capable of performing process listings.

### S0081 - Elise

Elise enumerates processes via the <code>tasklist</code> command.

### S1247 - Embargo

Embargo has utilized MS4Killer to detect running processes on the victim device. Embargo has also captured a snapshot of active running processes using the Windows API `CreateToolHelp32Snapshot()`.

### S0367 - Emotet

Emotet has been observed enumerating local processes.

### S0363 - Empire

Empire can find information about processes running on local and remote systems.

### S0091 - Epic

Epic uses the <code>tasklist /v</code> command to obtain a list of processes.

### S0396 - EvilBunny

EvilBunny has used EnumProcesses() to identify how many process are running in the environment.

### S0267 - FELIXROOT

FELIXROOT collects a list of running processes.

### S0512 - FatDuke

FatDuke can list running processes on the localhost.

### S0182 - FinFisher

FinFisher checks its parent process for indications that it is running in a sandbox setup.

### S0355 - Final1stspy

Final1stspy obtains a list of running processes.

### S0696 - Flagpro

Flagpro has been used to run the <code>tasklist</code> command on a compromised system.

### S0661 - FoggyWeb

FoggyWeb's loader can enumerate all Common Language Runtimes (CLRs) and running Application Domains in the compromised AD FS server's <code>Microsoft.IdentityServer.ServiceHost.exe</code> process.

### S0503 - FrameworkPOS

FrameworkPOS can enumerate and exclude selected processes on a compromised host to speed execution of memory scraping.

### S0277 - FruitFly

FruitFly has the ability to list processes on the system.

### S1044 - FunnyDream

FunnyDream has the ability to discover processes, including `Bka.exe` and `BkavUtil.exe`.

### S0410 - Fysbis

Fysbis can collect information about running processes.

### S0666 - Gelsemium

Gelsemium can enumerate running processes.

### S0049 - GeminiDuke

GeminiDuke collects information on running processes and environment variables from the victim.

### S0460 - Get2

Get2 has the ability to identify running processes on an infected host.

### S0249 - Gold Dragon

Gold Dragon checks the running processes on the victim’s machine.

### S0477 - Goopy

Goopy has checked for the Google Updater process to ensure Goopy was loaded properly.

### S0531 - Grandoreiro

Grandoreiro can identify installed security tools based on process names.

### S0237 - GravityRAT

GravityRAT lists the running processes on the system.

### S0151 - HALFBAKED

HALFBAKED can obtain information about running processes on the victim.

### S0617 - HELLOKITTY

HELLOKITTY can search for specific processes to terminate.

### S1230 - HIUPAN

HIUPAN has conducted process discovery to identify the PUBLOAD malware under the process WCBrowserWatcher.exe and will launch it from an install directory if it is not found.

### S1229 - Havoc

Havoc can enumerate processes on targeted hosts.

### S0170 - Helminth

Helminth has used Tasklist to get information on processes.

### S1027 - Heyoka Backdoor

Heyoka Backdoor can gather process information.

### S0431 - HotCroissant

HotCroissant has the ability to list running processes on the infected host.

### S0203 - Hydraq

Hydraq creates a backdoor through which remote attackers can monitor processes.

### S1139 - INC Ransomware

INC Ransomware can use the Microsoft Win32 Restart Manager to kill processes with a specific handle or that are accessing resources it wants to encrypt.

### S1132 - IPsec Helper

IPsec Helper can identify the process it is currently running under and its number, and pass this back to a command and control node.

### S0434 - Imminent Monitor

Imminent Monitor has a "Process Watcher" feature to monitor processes in case the client ever crashes or gets closed.

### S1072 - Industroyer2

Industroyer2 has the ability to cyclically enumerate running processes such as PServiceControl.exe, PService_PDD.exe, and other targets supplied through a hardcoded configuration.

### S0260 - InvisiMole

InvisiMole can obtain a list of running processes.

### S1245 - InvisibleFerret

InvisibleFerret has the capability to query installed programs and running processes. InvisibleFerret has also identified running processes using the Python project “psutil”.

### S0581 - IronNetInjector

IronNetInjector can identify processes via C# methods such as <code>GetProcessesByName</code> and running Tasklist with the Python <code>os.popen</code> function.

### S0015 - Ixeshe

Ixeshe can list running processes.

### S0044 - JHUHUGIT

JHUHUGIT obtains a list of running processes on the victim.

### S0201 - JPIN

JPIN can list running processes.

### S0528 - Javali

Javali can monitor processes for open browsers and custom banking applications.

### S0271 - KEYMARBLE

KEYMARBLE can obtain a list of running processes on the system.

### S0356 - KONNI

KONNI has used the command <code>cmd /c tasklist</code> to get a snapshot of the current processes on the target machine.

### S1075 - KOPILUWAK

KOPILUWAK can enumerate current running processes on the targeted machine.

### S0088 - Kasidet

Kasidet has the ability to search for a given process name in processes currently running in the system.

### S0265 - Kazuar

Kazuar obtains a list of running processes through WMI querying and the <code>ps</code> command.

### S0607 - KillDisk

KillDisk has called <code>GetCurrentProcess</code>.

### S0599 - Kinsing

Kinsing has used ps to list processes.

### S0162 - Komplex

The OsInfo function in Komplex collects a running process list.

### S0236 - Kwampirs

Kwampirs collects a list of running services with the command <code>tasklist /v</code>.

### S1160 - Latrodectus

Latrodectus can enumerate running processes including process grandchildren on targeted hosts.

### S1185 - LightSpy

If sent the command `16002`, LightSpy uses the `NSWorkspace runningApplications()` method to collect the process ID, path to the executable, bundle information, and the filename of the executable for all running applications.

### S0211 - Linfo

Linfo creates a backdoor through which remote attackers can retrieve a list of running processes.

### S0681 - Lizar

Lizar has a plugin designed to obtain a list of processes.

### S1199 - LockBit 2.0

LockBit 2.0 can determine if a running process has administrative privileges and terminate processes that interfere with encryption or exfiltration.

### S1202 - LockBit 3.0

LockBit 3.0 can identify and terminate specific services.

### S0582 - LookBack

LookBack can list running processes.

### S0451 - LoudMiner

LoudMiner used the <code>ps</code> command to monitor the running processes on the system.

### S0532 - Lucifer

Lucifer can identify the process that owns remote connections.

### S1141 - LunarWeb

LunarWeb has used shell commands to list running processes.

### S1016 - MacMa

MacMa can enumerate running processes.

### S0409 - Machete

Machete has a component to check for running processes to look for web browsers.

### S1060 - Mafalda

Mafalda can enumerate running processes on a machine.

### S0652 - MarkiRAT

MarkiRAT can search for different processes on a system.

### S0449 - Maze

Maze has gathered all of the running system processes.

### S1244 - Medusa Ransomware

Medusa Ransomware has utilized an encoded list of the processes that it detects and terminates.

### S1191 - Megazord

Megazord can terminate a list of specified services and processes.

### S0455 - Metamorfo

Metamorfo has performed process name checks and has monitored applications.

### S0688 - Meteor

Meteor can check if a specific process is running, such as Kaspersky's `avp.exe`.

### S1146 - MgBot

MgBot includes a module for establishing a process watchdog for itself, identifying if the MgBot process is still running.

### S1122 - Mispadu

Mispadu can enumerate the running processes on a compromised host.

### S0079 - MobileOrder

MobileOrder has a command to upload information about all running processes to its C2 server.

### S0149 - MoonWind

MoonWind has a command to return a list of running processes.

### S0256 - Mosquito

Mosquito runs <code>tasklist</code> to obtain running processes.

### S0034 - NETEAGLE

NETEAGLE can send process listings over the C2 channel.

### S0198 - NETWIRE

NETWIRE can discover processes on compromised hosts.

### S1107 - NKAbuse

NKAbuse will check victim systems to ensure only one copy of the malware is running.

### S0247 - NavRAT

NavRAT uses <code>tasklist /v</code> to check running processes.

### S0630 - Nebulae

Nebulae can enumerate processes on a target system.

### S1090 - NightClub

NightClub has the ability to use `GetWindowThreadProcessId` to identify the process behind a specified window.

### S1147 - Nightdoor

Nightdoor can collect information on installed applications via Windows registry keys, as well as collecting information on running processes.

### S1100 - Ninja

Ninja can enumerate processes on a targeted host.

### S0644 - ObliqueRAT

ObliqueRAT can check for blocklisted process names on a compromised host.

### S0346 - OceanSalt

OceanSalt can collect the name and ID for every process running on the system.

### S0229 - Orz

Orz can gather a process list from the victim.

### S1017 - OutSteel

OutSteel can identify running processes on a compromised host.

### S0626 - P8RAT

P8RAT can check for specific processes associated with virtual environments.

### S1233 - PAKLOG

PAKLOG has detected and logged the full path of processes active in the foreground using Windows API calls.

### S0254 - PLAINTEE

PLAINTEE performs the <code>tasklist</code> command to list running processes.

### S0435 - PLEAD

PLEAD has the ability to list processes on the compromised host.

### S0216 - POORAIM

POORAIM can enumerate processes.

### S0223 - POWERSTATS

POWERSTATS has used <code>get_tasklist</code> to discover processes on the compromised host.

### S0184 - POWRUNER

POWRUNER may collect process information by running <code>tasklist</code> on a victim.

### S1228 - PUBLOAD

PUBLOAD has used `tasklist` to gather running processes on victim host. PUBLOAD has also leveraged the `OpenEventA` Windows API function to check whether the same process was already running.

### S0664 - Pandora

Pandora can monitor processes on a compromised host.

### S0208 - Pasam

Pasam creates a backdoor through which remote attackers can retrieve lists of running processes.

### S1050 - PcShare

PcShare can obtain a list of running processes on a compromised host.

### S0517 - Pillowmint

Pillowmint can iterate through running processes every six seconds collecting a list of processes to capture from later.

### S0501 - PipeMon

PipeMon can iterate over the running processes to find a suitable injection target.

### S0013 - PlugX

PlugX has a module to list the processes running on a machine.

### S0428 - PoetRAT

PoetRAT has the ability to list all running processes.

### S0139 - PowerDuke

PowerDuke has a command to list the victim's processes.

### S0441 - PowerShower

PowerShower has the ability to deploy a reconnaissance module to retrieve a list of the active processes.

### S0194 - PowerSploit

PowerSploit's <code>Get-ProcessTokenPrivilege</code> Privesc-PowerUp module can enumerate privileges for a given process.

### S0393 - PowerStallion

PowerStallion has been used to monitor process lists.

### S0238 - Proxysvc

Proxysvc lists processes running on the system.

### S0192 - Pupy

Pupy can list the running processes and get the process ID and parent process’s ID.

### S0650 - QakBot

QakBot has the ability to check running processes.

### S1242 - Qilin

Qilin can define specific processes to be terminated or left alone at execution.

### S0241 - RATANKBA

RATANKBA lists the system’s processes.

### S0662 - RCSession

RCSession can identify processes based on PID.

### S0240 - ROKRAT

ROKRAT can list the current running processes on the system.

### S0148 - RTM

RTM can obtain information about process integrity levels.

### S0629 - RainyDay

RainyDay can enumerate processes on a target system.

### S0458 - Ramsay

Ramsay can gather a list of running processes by using Tasklist.

### S1212 - RansomHub

RansomHub can stop processes associated with files currently in use to maximize the impact of encryption.

### S1130 - Raspberry Robin

Raspberry Robin can identify processes running on the victim machine, such as security software, during execution.

### S0125 - Remsec

Remsec can obtain a process list from the victim.

### S0448 - Rising Sun

Rising Sun can enumerate all running processes and process information on an infected machine.

### S0270 - RogueRobin

RogueRobin checks the running processes for evidence it may be running in a sandbox environment. It specifically enumerates processes for Wireshark and Sysinternals.

### S1078 - RotaJakiro

RotaJakiro can monitor the `/proc/[PID]` directory of known RotaJakiro processes as a part of its persistence when executing with non-root permissions. If the process is found dead, it resurrects the process. RotaJakiro processes can be matched to an associated Advisory Lock, in the `/proc/locks` folder, to ensure it doesn't spawn more than one process.

### S1073 - Royal

Royal can use `GetCurrentProcess` to enumerate processes.

### S0446 - Ryuk

Ryuk has called <code>CreateToolhelp32Snapshot</code> to enumerate all running processes.

### S0461 - SDBbot

SDBbot can enumerate a list of running processes on a compromised machine.

### S0063 - SHOTPUT

SHOTPUT has a command to obtain a process listing.

### S0692 - SILENTTRINITY

SILENTTRINITY can enumerate processes, including properties to determine if they have the Common Language Runtime (CLR) loaded.

### S0533 - SLOTHFULMEDIA

SLOTHFULMEDIA has enumerated processes by ID, name, or privileges.

### S0559 - SUNBURST

SUNBURST collected a list of process names that were hashed using a FNV-1a + XOR algorithm to check against similarly-hashed hardcoded blocklists.

### S0562 - SUNSPOT

SUNSPOT monitored running processes for instances of <code>MsBuild.exe</code> by hashing the name of each running process and comparing it to the corresponding value <code>0x53D525</code>. It also extracted command-line arguments and individual arguments from the running <code>MsBuild.exe</code> process to identify the directory path of the Orion software Visual Studio solution.

### S1064 - SVCReady

SVCReady can collect a list of running processes from an infected host.

### S0464 - SYSCON

SYSCON has the ability to use Tasklist to list running processes.

### S1210 - Sagerunex

Sagerunex identifies the `explorer.exe` process on the executing system.

### S1018 - Saint Bot

Saint Bot has enumerated running processes on a compromised host to determine if it is running under the process name `dfrgui.exe`.

### S1085 - Sardonic

Sardonic has the ability to execute the `tasklist` command.

### S0345 - Seasalt

Seasalt has a command to perform a process listing.

### S0596 - ShadowPad

ShadowPad has collected the PID of a malicious process.

### S0445 - ShimRatReporter

ShimRatReporter listed all running processes on the machine.

### S1178 - ShrinkLocker

ShrinkLocker checks whether the Bitlocker Drive Encryption Tools service is running.

### S0468 - Skidmap

Skidmap has monitored critical processes to ensure resiliency.

### S1124 - SocGholish

SocGholish can list processes on targeted hosts.

### S0273 - Socksbot

Socksbot can list all running processes.

### S0627 - SodaMaster

SodaMaster can search a list of running processes.

### S0615 - SombRAT

SombRAT can use the <code>getprocesslist</code> command to enumerate processes on a compromised host.

### S0516 - SoreFang

SoreFang can enumerate processes on a victim machine through use of Tasklist.

### S0142 - StreamEx

StreamEx has the ability to enumerate processes.

### S0491 - StrongPity

StrongPity can determine if a user is logged in by checking to see if explorer.exe is running.

### S0018 - Sykipot

Sykipot may gather a list of running processes by running <code>tasklist /v</code>.

### S0242 - SynAck

SynAck enumerates all running processes.

### S0663 - SysUpdate

SysUpdate can collect information about running processes.

### S0586 - TAINTEDSCRIBE

TAINTEDSCRIBE can execute <code>ProcessList</code> for process discovery.

### S1239 - TONESHELL

TONESHELL has checked the process name and process path to ensure it matches the expected one prior to triggering a custom exception handler. TONESHELL has also searched for running antivirus processes to include ESET’s antivirus associated executables ekrn.exe and egui.exe.

### S0436 - TSCookie

TSCookie has the ability to list processes on the infected host.

### S0011 - Taidoor

Taidoor can use <code>GetCurrentProcessId</code> for process discovery.

### S0467 - TajMahal

TajMahal has the ability to identify running processes and associated plugins on an infected host.

### S0057 - Tasklist

Tasklist can be used to discover processes running on a system.

### S0595 - ThiefQuest

ThiefQuest obtains a list of running processes using the function <code>kill_unwanted</code>.

### S0266 - TrickBot

TrickBot uses module networkDll for process list discovery.

### S0094 - Trojan.Karagany

Trojan.Karagany can use Tasklist to collect a list of running tasks.

### S0333 - UBoatRAT

UBoatRAT can list running processes on the system.

### S1164 - UPSTYLE

UPSTYLE has the ability to read `/proc/self/cmdline` to see if it is running as a monitored process.

### S0452 - USBferry

USBferry can use <code>tasklist</code> to gather information about the process running on the infected system.

### S0022 - Uroburos

Uroburos can use its `Process List` command to enumerate processes on compromised hosts.

### S0386 - Ursnif

Ursnif has gathered information about running processes.

### S0257 - VERMIN

VERMIN can get a list of the processes and running tasks on the system.

### S0476 - Valak

Valak has the ability to enumerate running processes on a compromised host.

### S0180 - Volgmer

Volgmer can gather a list of processes.

### S0219 - WINERACK

WINERACK can enumerate processes.

### S0670 - WarzoneRAT

WarzoneRAT can obtain a list of processes on a compromised host.

### S0579 - Waterbear

Waterbear can identify the process for a specific security product.

### S0059 - WinMM

WinMM sets a WH_CBT Windows hook to collect information on process creation.

### S0141 - Winnti for Windows

Winnti for Windows can check if the explorer.exe process is responsible for calling its install function.

### S1065 - Woody RAT

Woody RAT can call `NtQuerySystemProcessInformation` with `SystemProcessInformation` to enumerate all running processes, including associated information such as PID, parent PID, image name, and owner.

### S0161 - XAgentOSX

XAgentOSX contains the getProcessList function to run <code>ps aux</code> to get running processes.

### S1114 - ZIPLINE

ZIPLINE can identify running processes and their names.

### S0251 - Zebrocy

Zebrocy uses the <code>tasklist</code> and <code>wmic process get Capture, ExecutablePath</code> commands to gather the processes running on the system.

### S0330 - Zeus Panda

Zeus Panda checks for running processes on the victim’s machine.

### S0672 - Zox

Zox has the ability to list processes.

### S0412 - ZxShell

ZxShell has a command, ps, to obtain a listing of processes on the system.

### S1013 - ZxxZ

ZxxZ has created a snapshot of running processes using `CreateToolhelp32Snapshot`.

### S0472 - down_new

down_new has the ability to list running processes on a compromised host.

### S0032 - gh0st RAT

gh0st RAT has the capability to list processes.

### S0278 - iKitten

iKitten lists the current processes running.

### S0283 - jRAT

jRAT can query and kill system processes.

### S1048 - macOS.OSAMiner

macOS.OSAMiner has used `ps ax | grep <name> | grep -v grep | ...` and `ps ax | grep -E...` to conduct process discovery.

### S1059 - metaMain

metaMain can enumerate the processes that run on the platform.

### S0385 - njRAT

njRAT can search a list of running processes for Tr.exe.

### S0248 - yty

yty gets an output of running processes using the <code>tasklist</code> command.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0015 - C0015

During C0015, the threat actors used the `tasklist /s` command as well as `taskmanager` to obtain a list of running processes.

### C0001 - Frankenstein

During Frankenstein, the threat actors used Empire to obtain a list of all running processes.

### C0007 - FunnyDream

During FunnyDream, the threat actors used Tasklist on targeted systems.

### C0035 - KV Botnet Activity

Scripts associated with KV Botnet Activity initial deployment can identify processes related to security tools and other botnet families for follow-on disabling during installation.

### C0012 - Operation CuckooBees

During Operation CuckooBees, the threat actors used the `tasklist` command as part of their advanced reconnaissance.

### C0006 - Operation Honeybee

During Operation Honeybee, the threat actors obtained a list of running processes on a victim machine using `cmd /c tasklist > %temp%\temp.ini`.

### C0014 - Operation Wocao

During Operation Wocao, the threat actors used `tasklist` to collect a list of running processes on an infected system.

### C0056 - RedPenguin

During RedPenguin, UNC3886 used malware capable of reading the PID for the Junos OS snmpd daemon.

### C0024 - SolarWinds Compromise

During the SolarWinds Compromise, APT29 used multiple command-line utilities to enumerate running processes.
