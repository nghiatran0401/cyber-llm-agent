# T1082 - System Information Discovery

**Tactic:** Discovery
**Platforms:** ESXi, IaaS, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1082

## Description

An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use this information to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions. This behavior is distinct from Local Storage Discovery which is an adversary's discovery of local drive, disks and/or volumes.

Tools such as Systeminfo can be used to gather detailed system information. If running with privileged access, a breakdown of system data can be gathered through the <code>systemsetup</code> configuration tool on macOS. Adversaries may leverage a Network Device CLI on network devices to gather detailed system information (e.g. <code>show version</code>). On ESXi servers, threat actors may gather system information from various esxcli utilities, such as `system hostname get` and `system version get`.

Infrastructure as a Service (IaaS) cloud providers such as AWS, GCP, and Azure allow access to instance and virtual machine information via APIs. Successful authenticated API calls can return data such as the operating system platform and status of a particular instance or the model view of a virtual machine.

System Information Discovery combined with information gathered from other forms of discovery and reconnaissance can drive payload development and concealment.

## Detection

### Detection Analytics

**Analytic 1452**

Process creation and command-line execution of native system discovery utilities such as `systeminfo`, `hostname`, `wmic`, or use of PowerShell/WMI for system enumeration.

**Analytic 1453**

Execution of system enumeration commands such as `uname`, `df`, `uptime`, `hostname`, `lscpu`, and `cat /etc/os-release` through local terminal or scripts.

**Analytic 1454**

Execution of system info utilities like `systemsetup`, `sw_vers`, `uname`, or `sysctl` by terminal or scripted processes.

**Analytic 1455**

Execution of `esxcli system hostname get`, `esxcli system version get`, or `esxcli hardware` commands through SSH or local shell.

**Analytic 1456**

Use of cloud API calls (e.g., AWS EC2 DescribeInstances, Azure VM Inventory) to enumerate system configurations across assets.

**Analytic 1457**

Execution of `show version`, `show hardware`, or `show system` commands through CLI via SSH or console.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0065 - 4H RAT

4H RAT sends an OS version identifier in its beacons.

### S0045 - ADVSTORESHELL

ADVSTORESHELL can run Systeminfo to gather information about the victim.

### S1167 - AcidPour

AcidPour can identify various system locations and mapped devices on Linux systems as a precursor to wiping activity.

### S1028 - Action RAT

Action RAT has the ability to collect the hostname, OS version, and OS architecture of an infected host.

### S0331 - Agent Tesla

Agent Tesla can collect the system's computer name and also has the capability to collect information on the processor, memory, OS, and video card from the system.

### S1129 - Akira

Akira uses the <code>GetSystemInfo</code> Windows function to determine the number of processors on a victim machine.

### S1025 - Amadey

Amadey has collected the computer name and OS version from a compromised machine.

### S0504 - Anchor

Anchor can determine the hostname and linux version on a compromised host.

### S0584 - AppleJeus

AppleJeus has collected the victim host information after infection.

### S0622 - AppleSeed

AppleSeed can identify the OS version of a targeted system.

### S0456 - Aria-body

Aria-body has the ability to identify the hostname, computer name, Windows version, processor speed, and machine GUID on a compromised host.

### S0373 - Astaroth

Astaroth collects the machine name and keyboard language from the system.

### S1029 - AuTo Stealer

AuTo Stealer has the ability to collect the hostname and OS information from an infected host.

### S0473 - Avenger

Avenger has the ability to identify the OS architecture on a compromised host.

### S0344 - Azorult

Azorult can collect the machine information, system architecture, the OS version, computer name, Windows product name, the number of CPU cores, video card information, and the system language.

### S0031 - BACKSPACE

During its initial execution, BACKSPACE extracts operating system information from the infected host.

### S0245 - BADCALL

BADCALL collects the computer name and host name on the compromised system.

### S0642 - BADFLICK

BADFLICK has captured victim computer name, memory space, and CPU details.

### S1081 - BADHATCH

BADHATCH can obtain current system information from a compromised machine such as the `SHELL PID`, `PSVERSION`, `HOSTNAME`, `LOGONSERVER`, `LASTBOOTUP`, OS type/version, bitness, and hostname.

### S0017 - BISCUIT

BISCUIT has a command to collect the processor type, operation system, computer name, and whether the system is a laptop or PC.

### S0520 - BLINDINGCAN

BLINDINGCAN has collected from a victim machine the system name, processor information, and OS version.

### S0657 - BLUELIGHT

BLUELIGHT has collected the computer name and OS version from victim machines.

### S1184 - BOLDMOVE

BOLDMOVE performs system survey actions following initial execution.

### S0043 - BUBBLEWRAP

BUBBLEWRAP collects system information, including the operating system version and hostname.

### S0414 - BabyShark

BabyShark has executed the <code>ver</code> command.

### S0475 - BackConfig

BackConfig has the ability to gather the victim's computer name.

### S0093 - Backdoor.Oldrea

Backdoor.Oldrea collects information about the OS and computer name.

### S0337 - BadPatch

BadPatch collects the OS system, OS version, MAC address, and the computer name from the victim’s machine.

### S0239 - Bankshot

Bankshot gathers system information, network addresses, and the operation system version.

### S0534 - Bazar

Bazar can fingerprint architecture, computer name, and OS version on the compromised host. Bazar can also check if the Russian language is installed on the infected machine and terminate if it is found.

### S1246 - BeaverTail

BeaverTail has been known to collect basic system information. BeaverTail has also collected data to include hostname and current timestamp prior to uploading data to the API endpoint `/uploads` on the C2 server.

### S0268 - Bisonal

Bisonal has used commands and API calls to gather system information.

### S1070 - Black Basta

Black Basta can collect system boot configuration and CPU information.

### S1180 - BlackByte Ransomware

BlackByte Ransomware gathers victim system information to generate a unique victim identifier.

### S1068 - BlackCat

BlackCat can obtain the computer name and UUID.

### S0089 - BlackEnergy

BlackEnergy has used Systeminfo to gather the OS version, as well as information on the system configuration, BIOS, the motherboard, and the processor.

### S0486 - Bonadan

Bonadan has discovered the OS version, CPU model, and RAM size of the system it has been installed on.

### S0635 - BoomBox

BoomBox can enumerate the hostname, domain, and IP of a compromised host.

### S0252 - Brave Prince

Brave Prince collects hard drive content and system configuration information.

### S1039 - Bumblebee

Bumblebee can enumerate the OS version and domain on a targeted system.

### S0482 - Bundlore

Bundlore will enumerate the macOS version to determine which follow-on behaviors to execute using <code>/usr/bin/sw_vers -productVersion</code>.

### S0462 - CARROTBAT

CARROTBAT has the ability to determine the operating system of the compromised host and whether Windows is being run with x86 or x64 architecture.

### S0137 - CORESHELL

CORESHELL collects hostname and OS version data from the victim and sends the information to its C2 server.

### S0693 - CaddyWiper

CaddyWiper can use `DsRoleGetPrimaryDomainInformation` to determine the role of the infected machine. CaddyWiper can also halt execution if the compromised host is identified as a domain controller.

### S0454 - Cadelspy

Cadelspy has the ability to discover information about the compromised host.

### S0351 - Cannon

Cannon can gather system information from the victim’s machine such as the OS version, and machine name.

### S0484 - Carberp

Carberp has collected the operating system version from the infected system.

### S0348 - Cardinal RAT

Cardinal RAT can collect the hostname, Microsoft Windows version, and processor architecture from a victim machine.

### S0572 - Caterpillar WebShell

Caterpillar WebShell has a module to gather information from the compromised asset, including the computer version, computer name, IIS version, and more.

### S0144 - ChChes

ChChes collects the victim hostname, window resolution, and Microsoft Windows version.

### S0631 - Chaes

Chaes has collected system information, including the machine name and OS version.

### S0674 - CharmPower

CharmPower can enumerate the OS version and computer name on a targeted system.

### S0667 - Chrommme

Chrommme has the ability to obtain the computer name of a compromised host.

### S0660 - Clambling

Clambling can discover the hostname, computer name, and Windows version of a targeted machine.

### S0244 - Comnie

Comnie collects the hostname of the victim machine.

### S1155 - Covenant

Covenant implants can gather basic information on infected systems.

### S0046 - CozyCar

A system info module in CozyCar gathers information on the victim host’s configuration.

### S0115 - Crimson

Crimson contains a command to collect the victim PC name and operating system.

### S1153 - Cuckoo Stealer

Cuckoo Stealer can gather information about the OS version and hardware on compromised hosts.

### S0687 - Cyclops Blink

Cyclops Blink has the ability to query device information.

### S1052 - DEADEYE

DEADEYE can enumerate a victim computer's volume serial number and host name.

### S1159 - DUSTTRAP

DUSTTRAP reads the value of the infected system's `HKLM\SYSTEM\Microsoft\Cryptography\MachineGUID` value.

### S0334 - DarkComet

DarkComet can collect the computer name, RAM used, and operating system version from the victim’s machine.

### S1111 - DarkGate

DarkGate will gather various system information such as domain, display adapter description, operating system type and version, processor type, and RAM amount.

### S1066 - DarkTortilla

DarkTortilla can obtain system information by querying the `Win32_ComputerSystem`, `Win32_BIOS`, `Win32_MotherboardDevice`, `Win32_PnPEntity`, and `Win32_DiskDrive` WMI objects.

### S0673 - DarkWatchman

DarkWatchman can collect the OS version, system architecture, and computer name.

### S0354 - Denis

Denis collects OS information and the computer name from the victim’s machine.

### S0021 - Derusbi

Derusbi gathers the name of the local host, version of GNU Compiler Collection (GCC), and the system information about the CPU, machine, and operating system.

### S0659 - Diavol

Diavol can collect the computer name and OS version from the system.

### S0186 - DownPaper

DownPaper collects the victim host name and serial number, and then sends the information to the C2 server.

### S0384 - Dridex

Dridex has collected the computer name and OS architecture information from the system.

### S0547 - DropBook

DropBook has checked for the presence of Arabic language in the infected machine's settings.

### S0567 - Dtrack

Dtrack can collect the victim's computer name, hostname and adapter information to create a unique identifier.

### S0062 - DustySky

DustySky extracts basic information about the operating system.

### S0024 - Dyre

Dyre has the ability to identify the computer name, OS version, and hardware configuration on a compromised host.

### S0568 - EVILNUM

EVILNUM can obtain the computer name from the victim's system.

### S0554 - Egregor

Egregor can perform a language check of the infected system and can query the CPU information (cupid).

### S0081 - Elise

Elise executes <code>systeminfo</code> after initial communication is made to the remote server.

### S0082 - Emissary

Emissary has the capability to execute ver and systeminfo commands.

### S0363 - Empire

Empire can enumerate host system information like OS, architecture, domain name, applied patches, and more.

### S0634 - EnvyScout

EnvyScout can determine whether the ISO payload was received by a Windows or iOS device.

### S0091 - Epic

Epic collects the OS version, hardware information, computer name, available system memory status, and system and user language settings.

### S0569 - Explosive

Explosive has collected the computer name from the infected host.

### S0181 - FALLCHILL

FALLCHILL can collect operating system (OS) version information, processor information, and system name from the victim.

### S0267 - FELIXROOT

FELIXROOT collects the victim’s computer name, processor architecture, OS version, and system type.

### S0512 - FatDuke

FatDuke can collect the user name, Windows version, computer name, and available space on discs from a compromised host.

### S0171 - Felismus

Felismus collects the system information, including hostname and OS version, and sends it to the C2 server.

### S0679 - Ferocious

Ferocious can use <code>GET.WORKSPACE</code> in Microsoft Excel to determine the OS version of the compromised host.

### S0182 - FinFisher

FinFisher checks if the victim OS is 32 or 64-bit.

### S0355 - Final1stspy

Final1stspy obtains victim Microsoft Windows version information and CPU architecture.

### S0381 - FlawedAmmyy

FlawedAmmyy can collect the victim's operating system and computer name during the initial infection.

### S0410 - Fysbis

Fysbis has used the command <code>ls /etc | egrep -e"fedora\*|debian\*|gentoo\*|mandriva\*|mandrake\*|meego\*|redhat\*|lsb-\*|sun-\*|SUSE\*|release"</code> to determine which Linux OS version is running.

### S0417 - GRIFFON

GRIFFON has used a reconnaissance module that can be used to retrieve information about a victim's computer, including the resolution of the workstation .

### S0666 - Gelsemium

Gelsemium can determine the operating system and whether a targeted machine has a 32 or 64 bit architecture.

### S0460 - Get2

Get2 has the ability to identify the computer name and Windows version of an infected host.

### S0249 - Gold Dragon

Gold Dragon collects endpoint information using the <code>systeminfo</code> command.

### S0493 - GoldenSpy

GoldenSpy has gathered operating system information.

### S1198 - Gomir

Gomir collects information on infected systems such as hostname, username, CPU, and RAM information.

### S1138 - Gootloader

Gootloader can inspect the User-Agent string in GET request header information to determine the operating system of targeted systems.

### S0531 - Grandoreiro

Grandoreiro can collect the computer name and OS version from a compromised host.

### S0237 - GravityRAT

GravityRAT collects the MAC address, computer name, and CPU information.

### S0690 - Green Lambert

Green Lambert can use `uname` to identify the operating system name, version, and processor type.

### S0632 - GrimAgent

GrimAgent can collect the OS, and build version on a compromised host.

### S0151 - HALFBAKED

HALFBAKED can obtain information about the OS, processor, and BIOS.

### S0214 - HAPPYWORK

can collect system information, including computer name, system manufacturer, IsDebuggerPresent state, and execution path.

### S0391 - HAWKBALL

HAWKBALL can collect the OS version, architecture information, and computer name.

### S0376 - HOPLIGHT

HOPLIGHT has been observed collecting victim machine information like OS version.

### S1229 - Havoc

Havoc can gather system information including hostname, domain, and OS details.

### S0697 - HermeticWiper

HermeticWiper can determine the OS version and bitness on a targeted host.

### S1249 - HexEval Loader

HexEval Loader has identified the OS and MAC address of victim device through host fingerprinting scripting.

### S0601 - Hildegard

Hildegard has collected the host's OS, CPU, and memory information.

### S0431 - HotCroissant

HotCroissant has the ability to determine if the current user is an administrator, Windows product name, processor name, screen resolution, and physical RAM of the infected host.

### S0203 - Hydraq

Hydraq creates a backdoor through which remote attackers can retrieve information such as computer name, OS version, processor speed, memory size, and CPU speed.

### S1152 - IMAPLoader

IMAPLoader uses WMI queries to gather information about the victim machine.

### S1022 - IceApple

The IceApple Server Variable Dumper module iterates over all server variables present for the current request and returns them to the adversary.

### S0483 - IcedID

IcedID has the ability to identify the computer name and OS version on a compromised host.

### S0604 - Industroyer

Industroyer collects the victim machine’s Windows GUID.

### S0259 - InnaputRAT

InnaputRAT gathers system information.

### S0260 - InvisiMole

InvisiMole can gather information on the OS version, computer name, DEP policy, and memory size.

### S1245 - InvisibleFerret

InvisibleFerret has collected OS type, hostname and system version through the "pay" module. InvisibleFerret has also queried the victim device using Python scripts to obtain the User and Hostname.

### S0015 - Ixeshe

Ixeshe collects the computer name of the victim's system during the initial infection.

### S0201 - JPIN

JPIN can obtain system information such as OS version and disk space.

### S0215 - KARAE

KARAE can collect system information.

### S0271 - KEYMARBLE

KEYMARBLE has the capability to collect the computer name, language settings, the OS version, CPU information, and time elapsed since system start.

### S0669 - KOCTOPUS

KOCTOPUS has checked the OS version using `wmic.exe` and the `find` command.

### S0156 - KOMPROGO

KOMPROGO is capable of retrieving information about the infected system.

### S0356 - KONNI

KONNI can gather the OS version, architecture information, hostname, and RAM size information from the victim’s machine and has used <code>cmd /c systeminfo</code> command to get a snapshot of the current system state of the target machine.

### S1190 - Kapeka

Kapeka utilizes WinAPI calls and registry queries to gather system information.

### S0088 - Kasidet

Kasidet has the ability to obtain a victim's system name and operating system version.

### S0265 - Kazuar

Kazuar gathers information on the system.

### S0585 - Kerrdown

Kerrdown has the ability to determine if the compromised host is running a 32 or 64 bit OS architecture.

### S0487 - Kessel

Kessel has collected the system architecture, OS version, and MAC address information.

### S1020 - Kevin

Kevin can enumerate the OS version and hostname of a targeted machine.

### S0387 - KeyBoy

KeyBoy can gather extended system information, such as information about the operating system and memory.

### S0250 - Koadic

Koadic can obtain the OS version and build, computer name, and processor architecture from a compromised host.

### S0641 - Kobalos

Kobalos can record the hostname and kernel version of the target machine.

### S0236 - Kwampirs

Kwampirs collects OS version information such as registered owner details, manufacturer details, processor type, available storage, installed patches, hostname, version info, system date, and other system information by using the commands <code>systeminfo</code>, <code>net config workstation</code>, <code>hostname</code>, <code>ver</code>, <code>set</code>, and <code>date /t</code>.

### S1121 - LITTLELAMB.WOOLTEA

LITTLELAMB.WOOLTEA can check the type of Ivanti VPN device it is running on by executing `first_run()` to identify the first four bytes of the motherboard serial number.

### S1160 - Latrodectus

Latrodectus can gather operating system information.

### S0395 - LightNeuron

LightNeuron gathers the victim computer name using the Win32 API call <code>GetComputerName</code>.

### S1185 - LightSpy

LightSpy's second stage implant uses the `DeviceInformation` class to collect system information, including CPU usage, battery statistics, memory allocations, screen size, etc.

### S1186 - Line Dancer

Line Dancer can gather system configuration information by running the native `show configuration` command.

### S0211 - Linfo

Linfo creates a backdoor through which remote attackers can retrieve system information.

### S0513 - LiteDuke

LiteDuke can enumerate the CPUID and BIOS version on a compromised system.

### S0680 - LitePower

LitePower has the ability to enumerate the OS architecture.

### S0681 - Lizar

Lizar can collect the computer name from the machine.

### S1199 - LockBit 2.0

LockBit 2.0 can enumerate system information including hostname and domain information.

### S1202 - LockBit 3.0

LockBit 3.0 can enumerate system hostname and domain.

### S0447 - Lokibot

Lokibot has the ability to discover the computer name and Windows product name/version.

### S0451 - LoudMiner

LoudMiner has monitored CPU usage.

### S0532 - Lucifer

Lucifer can collect the computer name, system architecture, default language, and processor frequency of a compromised host.

### S1213 - Lumma Stealer

Lumma Stealer has gathered various system information from victim machines.

### S1142 - LunarMail

LunarMail can capture environmental variables on compromised hosts.

### S1141 - LunarWeb

LunarWeb can use WMI queries and shell commands such as systeminfo.exe to collect the operating system, BIOS version, and domain name of the targeted system.

### S0233 - MURKYTOP

MURKYTOP has the capability to retrieve information about the OS.

### S1016 - MacMa

MacMa can collect information about a compromised computer, including: Hardware UUID, Mac serial number, and macOS version.

### S0409 - Machete

Machete collects the hostname of the target computer.

### S1060 - Mafalda

Mafalda can collect the computer name of a compromised host.

### S1182 - MagicRAT

MagicRAT collects basic system information from victim machines.

### S1169 - Mango

Mango can collect the machine name of a compromised system which is later used as part of a unique victim identifier.

### S1156 - Manjusaka

Manjusaka performs basic system profiling actions to fingerprint and register the victim system with the C2 controller.

### S0652 - MarkiRAT

MarkiRAT can obtain the computer name from a compromised host.

### S0449 - Maze

Maze has checked the language of the infected system using the "GetUSerDefaultUILanguage" function.

### S1244 - Medusa Ransomware

Medusa Ransomware has collected data from the SMBIOS firmware table using `GetSystemFirmwareTable`.

### S0455 - Metamorfo

Metamorfo has collected the hostname and operating system version from the compromised host.

### S0688 - Meteor

Meteor has the ability to discover the hostname of a compromised host.

### S0339 - Micropsia

Micropsia gathers the hostname and OS version from the victim’s machine.

### S1015 - Milan

Milan can enumerate the targeted machine's name and GUID.

### S0051 - MiniDuke

MiniDuke can gather the hostname on a compromised machine.

### S0280 - MirageFox

MirageFox can collect CPU and architecture information from the victim’s machine.

### S0084 - Mis-Type

The initial beacon packet for Mis-Type contains the operating system version and file system of the victim.

### S0083 - Misdat

The initial beacon packet for Misdat contains the operating system version of the victim.

### S1122 - Mispadu

Mispadu collects the OS version, computer name, and language ID.

### S0079 - MobileOrder

MobileOrder has a command to upload to its C2 server victim mobile device information, including IMEI, IMSI, SIM card serial number, phone number, Android version, and other information.

### S0553 - MoleNet

MoleNet can collect information about the about the system.

### S1026 - Mongall

Mongall can retrieve the hostname via `gethostbyname`.

### S0149 - MoonWind

MoonWind can obtain the victim hostname, Windows version, RAM amount, and screen resolution.

### S0284 - More_eggs

More_eggs has the capability to gather the OS version and computer name.

### S0272 - NDiskMonitor

NDiskMonitor obtains the victim computer name and encrypts the information to send over its C2 channel.

### S0198 - NETWIRE

NETWIRE can discover and collect victim system information.

### S1107 - NKAbuse

NKAbuse conducts multiple system checks and includes these in subsequent "heartbeat" messages to the malware's command and control server.

### S0353 - NOKKI

NOKKI can gather information on the operating system on the victim’s machine.

### S0205 - Naid

Naid collects a unique identifier (UID) from a compromised host.

### S0228 - NanHaiShu

NanHaiShu can gather the victim computer name and serial number.

### S0247 - NavRAT

NavRAT uses <code>systeminfo</code> on a victim’s machine.

### S0691 - Neoichor

Neoichor can collect the OS version and computer name from a compromised host.

### S0457 - Netwalker

Netwalker can determine the system architecture it is running on to choose which version of the DLL to use.

### S1147 - Nightdoor

Nightdoor gathers information on the victim system such as CPU and Computer name as well as device drivers.

### S1100 - Ninja

Ninja can obtain the computer name and information on the OS from targeted hosts.

### S0165 - OSInfo

OSInfo discovers information about the infected machine.

### S0402 - OSX/Shlayer

OSX/Shlayer has collected the IOPlatformUUID, session UID, and the OS version using the command <code>sw_vers -productVersion</code>.

### S0352 - OSX_OCEANLOTUS.D

OSX_OCEANLOTUS.D collects processor information, memory information, computer name, hardware UUID, serial number, and operating system version. OSX_OCEANLOTUS.D has used the <code>ioreg</code> command to gather some of this information.

### S0644 - ObliqueRAT

ObliqueRAT has the ability to check for blocklisted computer names on infected endpoints.

### S0346 - OceanSalt

OceanSalt can collect the computer name from the system.

### S0340 - Octopus

Octopus can collect the computer name, OS version, and OS architecture information.

### S1172 - OilBooster

OilBooster can identify the compromised system's hostname which is used to create a unique identifier.

### S0439 - Okrum

Okrum can collect computer name, locale information, and information about the OS and architecture.

### S0264 - OopsIE

OopsIE checks for information on the CPU fan, temperature, mouse, hard disk, and motherboard as part of its anti-VM checks.

### S0229 - Orz

Orz can gather the victim OS version and whether it is 64 or 32 bit.

### S0254 - PLAINTEE

PLAINTEE collects general system enumeration data about the infected machine and checks the OS version.

### S0216 - POORAIM

POORAIM can identify system information, including battery status.

### S0223 - POWERSTATS

POWERSTATS can retrieve OS name/architecture and computer/domain name information from compromised hosts.

### S0184 - POWRUNER

POWRUNER may collect information about the system by running <code>hostname</code> and <code>systeminfo</code> on a victim.

### S1228 - PUBLOAD

PUBLOAD has collected and sent system information including volume serial number, computer name, and system uptime to designated C2.  PUBLOAD has also used several commands executed in sequence via `cmd` in a short interval to gather system information about the infected host including `systeminfo`. PUBLOAD has decrypted shellcode that collects the computer name.

### S0196 - PUNCHBUGGY

PUNCHBUGGY can gather system information such as computer names.

### S0208 - Pasam

Pasam creates a backdoor through which remote attackers can retrieve information like hostname.

### S0556 - Pay2Key

Pay2Key has the ability to gather the hostname of the victim machine.

### S0587 - Penquin

Penquin can report the file system type of a compromised host to C2.

### S1145 - Pikabot

Pikabot performs a variety of system checks and gathers system information, including commands such as <code>whoami</code>.

### S0048 - PinchDuke

PinchDuke gathers system configuration information.

### S1031 - PingPull

PingPull can retrieve the hostname of a compromised host.

### S0501 - PipeMon

PipeMon can collect and send OS version and computer name as a part of its C2 beacon.

### S0124 - Pisloader

Pisloader has a command to collect victim system information, including the system name and OS version.

### S0013 - PlugX

PlugX has collected system information including OS version, processor information, RAM size, location, host name, IP, and screen size of the infected host.

### S0428 - PoetRAT

PoetRAT has the ability to gather information about the compromised host.

### S0453 - Pony

Pony has collected the Service Pack, language, and region information to send to the C2.

### S0378 - PoshC2

PoshC2 contains modules, such as <code>Get-ComputerInfo</code>, for enumerating common system information.

### S0139 - PowerDuke

PowerDuke has commands to get information about the victim's name, build, version, serial number, and memory usage.

### S0441 - PowerShower

PowerShower has collected system information on the infected host.

### S0113 - Prikormka

A module in Prikormka collects information from the victim about Windows OS version, computer name, battery info, and physical memory.

### S0238 - Proxysvc

Proxysvc collects the OS version, country name, MAC address, computer name, and physical memory statistics.

### S0192 - Pupy

Pupy can grab a system’s information including the OS version, architecture, etc.

### S0650 - QakBot

QakBot can collect system information including the OS version and domain on a compromised host.

### S0262 - QuasarRAT

QuasarRAT can gather system information from the victim’s machine including the OS type.

### S0241 - RATANKBA

RATANKBA gathers information about the OS architecture, OS name, and OS version/Service pack.

### S0662 - RCSession

RCSession can gather system information from a compromised host.

### S0496 - REvil

REvil can identify the username, machine name, system language, keyboard layout, and OS version on a compromised host.

### S1222 - RIFLESPINE

RIFLESPINE can collect system information after installation on infected systems.

### S0240 - ROKRAT

ROKRAT can gather the hostname and the OS version to ensure it doesn’t run on a Windows XP or Windows Server 2003 systems.

### S0148 - RTM

RTM can obtain the computer name, OS version, and default language identifier.

### S1148 - Raccoon Stealer

Raccoon Stealer gathers information on infected systems such as operating system, processor information, RAM, and display information.

### S1212 - RansomHub

RansomHub can retrieve information about virtual machines.

### S1130 - Raspberry Robin

Raspberry Robin performs several system checks as part of anti-analysis mechanisms, including querying the operating system build number, processor vendor and type, video controller, and CPU temperature.

### S0172 - Reaver

Reaver collects system information from the victim, including CPU speed, computer name, ANSI code page, OEM code page identifier for the OS, Microsoft Windows version, and memory information.

### S0153 - RedLeaves

RedLeaves can gather extended system information including the hostname, OS version number, platform, memory information, time elapsed since system startup, and CPU information.

### S1240 - RedLine Stealer

RedLine Stealer can collect information about the local system.

### S0125 - Remsec

Remsec can obtain the OS version information, computer name, processor architecture, machine role, and OS edition.

### S0379 - Revenge RAT

Revenge RAT collects the CPU information, OS information, and system language.

### S0433 - Rifdoor

Rifdoor has the ability to identify the Windows version on the compromised host.

### S0448 - Rising Sun

Rising Sun can detect the computer name and operating system.

### S0270 - RogueRobin

RogueRobin gathers BIOS versions and manufacturers, the number of CPU cores, the total physical memory, and the computer name.

### S1078 - RotaJakiro

RotaJakiro executes a set of commands to collect device information, including `uname`.  Another example is the `cat /etc/*release | uniq` command used to collect the current OS distribution.

### S1073 - Royal

Royal can use `GetNativeSystemInfo` to enumerate system processors.

### S0253 - RunningRAT

RunningRAT gathers the OS version and processor information.

### S0085 - S-Type

The initial beacon packet for S-Type contains the operating system version and file system of the victim.

### S0461 - SDBbot

SDBbot has the ability to identify the OS version, OS bit information and computer name.

### S0450 - SHARPSTATS

SHARPSTATS has the ability to identify the IP address, machine name, and OS of the compromised host.

### S0217 - SHUTTERSPEED

SHUTTERSPEED can collect system information.

### S0692 - SILENTTRINITY

SILENTTRINITY can collect information related to a compromised host, including OS version.

### S0533 - SLOTHFULMEDIA

SLOTHFULMEDIA has collected system name, OS version, adapter information, and memory usage from a victim machine.

### S0218 - SLOWDRIFT

SLOWDRIFT collects and sends system information to its C2.

### S0649 - SMOKEDHAM

SMOKEDHAM has used the <code>systeminfo</code> command on a compromised host.

### S0157 - SOUNDBITE

SOUNDBITE is capable of gathering system information.

### S1037 - STARWHALE

STARWHALE can gather the computer name of an infected host.

### S0559 - SUNBURST

SUNBURST collected hostname and OS version.

### S1064 - SVCReady

SVCReady has the ability to collect information such as computer name, computer manufacturer, BIOS, operating system, and firmware, including through the use of `systeminfo.exe`.

### S0464 - SYSCON

SYSCON has the ability to use Systeminfo to identify system information.

### S1210 - Sagerunex

Sagerunex gathers information from the infected system such as hostname.

### S1018 - Saint Bot

Saint Bot can identify the OS version, CPU, and other details from a victim's machine.

### S1168 - SampleCheck5000

SampleCheck5000 can create unique victim identifiers by using the compromised system’s computer name.

### S1085 - Sardonic

Sardonic has the ability to collect the computer name, and CPU manufacturer name from a compromised machine. Sardonic also has the ability to execute the `ver` and `systeminfo` commands.

### S0382 - ServHelper

ServHelper will attempt to enumerate Windows version and system architecture.

### S0596 - ShadowPad

ShadowPad has discovered system information including memory status, CPU frequency, and OS versions.

### S0140 - Shamoon

Shamoon obtains the victim's operating system version and keyboard layout and sends the information to the C2 server.

### S1019 - Shark

Shark can collect the GUID of a targeted machine.

### S0546 - SharpStage

SharpStage has checked the system settings to see if Arabic is the configured language.

### S0445 - ShimRatReporter

ShimRatReporter gathered the operating system name and specific Windows version of an infected machine.

### S1178 - ShrinkLocker

ShrinkLocker uses WMI queries to gather various information about the victim machine and operating system.

### S0610 - SideTwist

SideTwist can collect the computer name of a targeted system.

### S0468 - Skidmap

Skidmap has the ability to check whether the infected system’s OS is Debian or RHEL/CentOS to determine which cryptocurrency miner it should use.

### S1086 - Snip3

Snip3 has the ability to query `Win32_ComputerSystem` for system information.

### S1124 - SocGholish

SocGholish has the ability to enumerate system information including the victim computer name.

### S0627 - SodaMaster

SodaMaster can enumerate the host name and OS version on a target system.

### S1166 - Solar

Solar can send basic information about the infected host to C2.

### S0615 - SombRAT

SombRAT can execute <code>getinfo</code> to enumerate the computer name and OS version of a compromised system.

### S0516 - SoreFang

SoreFang can collect the hostname, operating system configuration, and product ID on victim machines by executing Systeminfo.

### S0543 - Spark

Spark can collect the hostname, keyboard layout, and language from the system.

### S0374 - SpeakUp

SpeakUp uses the <code>cat /proc/cpuinfo | grep -c “cpu family” 2>&1</code> command to gather system information.

### S0646 - SpicyOmelette

SpicyOmelette can identify the system name of a compromised host.

### S1234 - SplatCloak

SplatCloak has collected the Windows build number using the windows kernel API `RtlGetVersion` to determine if the response is 19000 or higher (Windows 10 version 2004 or later).

### S1030 - Squirrelwaffle

Squirrelwaffle has gathered victim computer information and configurations.

### S0058 - SslMM

SslMM sends information to its hard-coded C2, including OS version, service pack information, processor speed, system name, and OS install date.

### S1200 - StealBit

StealBit can enumerate the computer name and domain membership of the compromised system.

### S0380 - StoneDrill

StoneDrill has the capability to discover the system OS, Windows version, architecture and environment.

### S0142 - StreamEx

StreamEx has the ability to enumerate system information.

### S1183 - StrelaStealer

StrelaStealer variants collect victim system information for exfiltration.

### S1034 - StrifeWater

StrifeWater can collect the OS version, architecture, and machine name to create a unique token for the infected host.

### S0603 - Stuxnet

Stuxnet collects system information including computer and domain names, OS version, and S7P paths.

### S0242 - SynAck

SynAck gathers computer names, OS version info, and also checks installed keyboard layouts to estimate if it has been launched from a certain list of countries.

### S0060 - Sys10

Sys10 collects the computer name, OS versioning information, and OS install date and sends the information to the C2.

### S0663 - SysUpdate

SysUpdate can collect a system's architecture, operating system version, and hostname.

### S0096 - Systeminfo

Systeminfo can be used to gather information about the operating system.

### S0098 - T9000

T9000 gathers and beacons the operating system build number and CPU Architecture (32-bit/64-bit) during installation.

### S1239 - TONESHELL

TONESHELL has the ability to retrieve the name of the infected machine.

### S0199 - TURNEDUP

TURNEDUP is capable of gathering system information.

### S0467 - TajMahal

TajMahal has the ability to identify hardware information, the computer name, and OS information on an infected host.

### S0665 - ThreatNeedle

ThreatNeedle can collect system profile information from a compromised host.

### S0266 - TrickBot

TrickBot gathers the OS version, machine name, CPU type, amount of RAM available, and UEFI/BIOS firmware information from the victim’s machine.

### S0094 - Trojan.Karagany

Trojan.Karagany can capture information regarding the victim's OS, security, and hardware configuration.

### S1196 - Troll Stealer

Troll Stealer can collect local system information.

### S0647 - Turian

Turian can retrieve system information including OS version, memory usage, local hostname, and system adapter information.

### S0275 - UPPERCUT

UPPERCUT has the capability to gather the system’s hostname and OS version.

### S0130 - Unknown Logger

Unknown Logger can obtain information about the victim computer name, physical memory, country, and date.

### S0022 - Uroburos

Uroburos has the ability to gather basic system information and run the POSIX API `gethostbyname`.

### S0386 - Ursnif

Ursnif has used Systeminfo to gather system information.

### S0257 - VERMIN

VERMIN collects the OS name, machine name, and architecture information.

### S0476 - Valak

Valak can determine the Windows version and computer name on a compromised host.

### S0180 - Volgmer

Volgmer can gather system information, the computer name, OS version, drive and serial information from the victim's machine.

### S0155 - WINDSHIELD

WINDSHIELD can gather the victim computer name.

### S0219 - WINERACK

WINERACK can gather information about the host.

### S0670 - WarzoneRAT

WarzoneRAT can collect compromised host information, including OS version, PC name, RAM size, and CPU details.

### S0514 - WellMess

WellMess can identify the computer name of a compromised host.

### S0059 - WinMM

WinMM collects the system name, OS version including service pack, and system install date and sends the information to the C2 server.

### S0176 - Wingbird

Wingbird checks the victim OS version after executing to determine where to drop files based on whether the victim is 32-bit or 64-bit.

### S0141 - Winnti for Windows

Winnti for Windows can determine if the OS on a compromised host is newer than Windows XP.

### S1065 - Woody RAT

Woody RAT can retrieve the following information from an infected machine: OS, architecture, computer name, OS build version, and environment variables.

### S0161 - XAgentOSX

XAgentOSX contains the getInstalledAPP function to run <code>ls -la /Applications</code> to gather what applications are installed.

### S0658 - XCSSET

XCSSET identifies the macOS version and uses <code>ioreg</code> to determine serial number.

### S1207 - XLoader

XLoader can collect system information and supported language information from the victim machine.

### S1248 - XORIndex Loader

XORIndex Loader has the ability to collect the hostname, OS Username, Geolocation, and OS version of an infected host.

### S0388 - YAHOYAH

YAHOYAH checks for the system’s Windows OS version and hostname.

### S0086 - ZLib

ZLib has the ability to enumerate system information.

### S0251 - Zebrocy

Zebrocy collects the OS version and computer name. Zebrocy also runs the <code>systeminfo</code> command to gather system information.

### S0230 - ZeroT

ZeroT gathers the victim's computer name, Windows version, and system language, and then sends it to its C2 server.

### S0330 - Zeus Panda

Zeus Panda collects the OS version, system architecture, computer name, product ID, install date, and information on the keyboard mapping to determine the language used on the system.

### S0412 - ZxShell

ZxShell can collect the local hostname, operating system details, CPU speed, and total physical memory.

### S1013 - ZxxZ

ZxxZ has collected the host name and operating system product name from a compromised machine.

### S0106 - cmd

cmd can be used to find information about the operating system.

### S0105 - dsquery

dsquery has the ability to enumerate various information, such as the operating system and host name, for systems within a domain.

### S0032 - gh0st RAT

gh0st RAT has gathered system architecture, processor, OS configuration, and installed hardware information.

### S0283 - jRAT

jRAT collects information about the OS (version, build type, install date) as well as system up-time upon receiving a connection from a backdoor.

### S1048 - macOS.OSAMiner

macOS.OSAMiner can gather the device serial number.

### S1059 - metaMain

metaMain can collect the computer name from a compromised host.

### S0385 - njRAT

njRAT enumerates the victim operating system and computer name during the initial infection.

### S0248 - yty

yty gathers the computer name, CPU information, Microsoft Windows version, and runs the command <code>systeminfo</code>.

### S0350 - zwShell

zwShell can obtain the victim PC name and OS version.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0046 - ArcaneDoor

ArcaneDoor included collection of victim device configuration information.

### C0029 - Cutting Edge

During Cutting Edge, threat actors used the ENUM4LINUX Perl script for discovery on Windows and Samba hosts.

### C0001 - Frankenstein

During Frankenstein, the threat actors used Empire to obtain the compromised machine's name.

### C0007 - FunnyDream

During FunnyDream, the threat actors used Systeminfo to collect information on targeted hosts.

### C0044 - Juicy Mix

During Juicy Mix, OilRig used a script to send the name of the compromised host via HTTP `POST` to register it with C2.

### C0035 - KV Botnet Activity

KV Botnet Activity includes use of native system tools, such as <code>uname</code>, to obtain information about victim device architecture, as well as gathering other system information such as the victim's hosts file and CPU utilization.

### C0049 - Leviathan Australian Intrusions

Leviathan performed host enumeration and data gathering operations on victim machines during Leviathan Australian Intrusions.

### C0012 - Operation CuckooBees

During Operation CuckooBees, the threat actors used the `systeminfo` command to gather details about a compromised system.

### C0006 - Operation Honeybee

During Operation Honeybee, the threat actors collected the computer name, OS, and other system information using `cmd /c systeminfo > %temp%\ temp.ini`.

### C0014 - Operation Wocao

During Operation Wocao, threat actors discovered the OS versions of systems connected to a targeted network.

### C0047 - RedDelta Modified PlugX Infection Chain Operations

Mustang Panda captured victim operating system type via User Agent analysis during RedDelta Modified PlugX Infection Chain Operations.

### C0058 - SharePoint ToolShell Exploitation

During SharePoint ToolShell Exploitation, threat actors fingerprinted targeted SharePoint servers to identify OS version and running processes.
