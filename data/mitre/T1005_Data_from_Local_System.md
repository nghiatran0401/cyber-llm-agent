# T1005 - Data from Local System

**Tactic:** Collection
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1005

## Description

Adversaries may search local system sources, such as file systems, configuration files, local databases, virtual machine files, or process memory, to find files of interest and sensitive data prior to Exfiltration.

Adversaries may do this using a Command and Scripting Interpreter, such as cmd as well as a Network Device CLI, which have functionality to interact with the file system to gather information. Adversaries may also use Automated Collection on the local system.

## Detection

### Detection Analytics

**Analytic 1070**

Adversaries collecting local files via PowerShell, WMI, or direct file API calls often include recursive file listings, targeted file reads, and temporary file staging.

**Analytic 1071**

Adversaries using bash scripts or tools to recursively enumerate user home directories, config files, or SSH keys.

**Analytic 1072**

Adversary use of bash/zsh or AppleScript to locate files and exfil targets like user keychains or documents.

**Analytic 1073**

Collection of device configuration via CLI commands (e.g., `show running-config`, `copy flash`, `more`), often followed by TFTP/SCP transfers.

**Analytic 1074**

Adversaries accessing datastore or configuration files via `vim-cmd`, `esxcli`, or SCP to extract logs, VMs, or host configurations.


## Mitigations

### M1057 - Data Loss Prevention

Data loss prevention can restrict access to sensitive data and detect sensitive data that is unencrypted.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1028 - Action RAT

Action RAT can collect local data from an infected machine.

### S1025 - Amadey

Amadey can collect information from a compromised host.

### S0622 - AppleSeed

AppleSeed can collect data on a compromised host.

### S1029 - AuTo Stealer

AuTo Stealer can collect data such as PowerPoint files, Word documents, Excel files, PDF files, text files, database files, and image files from an infected machine.

### S0642 - BADFLICK

BADFLICK has uploaded files from victims' machines.

### S0128 - BADNEWS

When it first starts, BADNEWS crawls the victim's local drives and collects documents with the following extensions: .doc, .docx, .pdf, .ppt, .pptx, and .txt.

### S0520 - BLINDINGCAN

BLINDINGCAN has uploaded files from victim machines.

### S0337 - BadPatch

BadPatch collects files from the local system that have the following extensions, then prepares them for exfiltration: .xls, .xlsx, .pdf, .mdb, .rar, .zip, .doc, .docx.

### S0234 - Bandook

Bandook can collect local files from the system .

### S0239 - Bankshot

Bankshot collects files from the local system.

### S0534 - Bazar

Bazar can retrieve information from the infected machine.

### S1246 - BeaverTail

BeaverTail has exfiltrated data collected from local systems.

### S0268 - Bisonal

Bisonal has collected information from a compromised host.

### S0564 - BlackMould

BlackMould can copy files on a compromised host.

### S0651 - BoxCaon

BoxCaon can upload files from a compromised host.

### S1063 - Brute Ratel C4

Brute Ratel C4 has the ability to upload files from a compromised system.

### S1039 - Bumblebee

Bumblebee can capture and compress stolen credentials from the Registry and volume shadow copies.

### S1224 - CASTLETAP

CASTLETAP can execute a C2 command to transfer files from victim machines.

### S1149 - CHIMNEYSWEEP

CHIMNEYSWEEP can collect files from compromised hosts.

### S0274 - Calisto

Calisto can collect data from user directories.

### S0572 - Caterpillar WebShell

Caterpillar WebShell has a module to collect information from the local database.

### S0674 - CharmPower

CharmPower can collect data and files from a compromised host.

### S0020 - China Chopper

China Chopper's server component can upload local files.

### S0667 - Chrommme

Chrommme can collect data from a local system.

### S0660 - Clambling

Clambling can collect information from a compromised host.

### S0154 - Cobalt Strike

Cobalt Strike can collect data from a local system.

### S0492 - CookieMiner

CookieMiner has retrieved iPhone text messages from iTunes phone backup files.

### S0050 - CosmicDuke

CosmicDuke steals user files from local hard drives with file extensions that match a predefined list.

### S1023 - CreepyDrive

CreepyDrive can upload files to C2 from victim machines.

### S0115 - Crimson

Crimson can collect information from a compromised host.

### S0538 - Crutch

Crutch can exfiltrate files from compromised systems.

### S0498 - Cryptoistic

Cryptoistic can retrieve files from the local file system.

### S0687 - Cyclops Blink

Cyclops Blink can upload files from a compromised host.

### S0694 - DRATzarus

DRATzarus can collect information from a compromised host.

### S1159 - DUSTTRAP

DUSTTRAP can gather data from infected systems.

### S1014 - DanBot

DanBot can upload files from compromised hosts.

### S1111 - DarkGate

DarkGate has stolen `sitemanager.xml` and `recentservers.xml` from `%APPDATA%\FileZilla\` if present.

### S0673 - DarkWatchman

DarkWatchman can collect files from a compromised host.

### S1021 - DnsSystem

DnsSystem can upload files from infected machines after receiving a command with `uploaddd` in the string.

### S0502 - Drovorub

Drovorub can transfer files from the victim machine.

### S0567 - Dtrack

Dtrack can collect a variety of information from victim machines.

### S0634 - EnvyScout

EnvyScout can collect sensitive NTLM material from a compromised host.

### S0036 - FLASHFLOOD

FLASHFLOOD searches for interesting files (either a default or customized set of file extensions) on the local system. FLASHFLOOD will scan the My Recent Documents, Desktop, Temporary Internet Files, and TEMP directories. FLASHFLOOD also collects information stored in the Windows Address Book.

### S0512 - FatDuke

FatDuke can copy files and directories from a compromised host.

### S0696 - Flagpro

Flagpro can collect data from a compromised host, including Windows authentication information.

### S0381 - FlawedAmmyy

FlawedAmmyy has collected information and files from a compromised machine.

### S0661 - FoggyWeb

FoggyWeb can retrieve configuration data from a compromised AD FS server.

### S0193 - Forfiles

Forfiles can be used to act on (ex: copy, move, etc.) files/directories in a system during (ex: copy files into a staging area before).

### S0503 - FrameworkPOS

FrameworkPOS can collect elements related to credit card data from process memory.

### S1044 - FunnyDream

FunnyDream can upload files from victims' machines.

### S0666 - Gelsemium

Gelsemium can collect data from a compromised host.

### S0477 - Goopy

Goopy has the ability to exfiltrate documents from infected systems.

### S0237 - GravityRAT

GravityRAT steals files with the following extensions: .docx, .doc, .pptx, .ppt, .xlsx, .xls, .rtf, and .pdf.

### S0690 - Green Lambert

Green Lambert can collect data from a compromised host.

### S0632 - GrimAgent

GrimAgent can collect data and files from a compromised host.

### S1229 - Havoc

Havoc can download files from the victim's computer.

### S0009 - Hikit

Hikit can upload files from compromised machines.

### S0203 - Hydraq

Hydraq creates a backdoor through which remote attackers can read data from files.

### S1132 - IPsec Helper

IPsec Helper can identify specific files and folders for follow-on exfiltration.

### S1022 - IceApple

IceApple can collect files, passwords, and other data from a compromised host.

### S0260 - InvisiMole

InvisiMole can collect data from the system, and can monitor changes in specified directories.

### S1245 - InvisibleFerret

InvisibleFerret has collected data utilizing a script that contained a list of excluded files and directory names and naming patterns of interest such as environment and configuration files, documents, spreadsheets, and other files that contained the words secret, wallet, private, and password.

### S0015 - Ixeshe

Ixeshe can collect data from a local system.

### S0526 - KGH_SPY

KGH_SPY can send a file containing victim system information to C2.

### S0356 - KONNI

KONNI has stored collected information and discovered processes in a tmp file.

### S1075 - KOPILUWAK

KOPILUWAK can gather information from compromised hosts.

### S0265 - Kazuar

Kazuar uploads files from a specified directory to the C2 server.

### S1020 - Kevin

Kevin can upload logs and other data from a compromised host.

### S0250 - Koadic

Koadic can download files off the target system to send back to the server.

### S1160 - Latrodectus

Latrodectus can collect data from a compromised host using a stealer module.

### S0395 - LightNeuron

LightNeuron can collect files from a local system.

### S0211 - Linfo

Linfo creates a backdoor through which remote attackers can obtain data from local systems.

### S1101 - LoFiSe

LoFiSe can collect files of interest from targeted systems.

### S0500 - MCMD

MCMD has the ability to upload files from an infected device.

### S1016 - MacMa

MacMa can collect then exfiltrate files from the compromised system.

### S0409 - Machete

Machete searches the File system for files of interest.

### S1060 - Mafalda

Mafalda can collect files and information from a compromised host.

### S0652 - MarkiRAT

MarkiRAT can upload data from the victim's machine to the C2 server.

### S1146 - MgBot

MgBot includes modules for collecting files from local systems based on a given set of properties and filenames.

### S1015 - Milan

Milan can upload files from a compromised host.

### S0084 - Mis-Type

Mis-Type has collected files and data from a compromised host.

### S0083 - Misdat

Misdat has collected files and data from a compromised host.

### S0079 - MobileOrder

MobileOrder exfiltrates data collected from the victim mobile device.

### S1026 - Mongall

Mongall has the ability to upload files from victim's machines.

### S1131 - NPPSPY

NPPSPY records data entered from the local system logon at Winlogon to capture credentials in cleartext.

### S0630 - Nebulae

Nebulae has the capability to upload collected files to C2.

### S0691 - Neoichor

Neoichor can upload files from a victim's machine.

### S1090 - NightClub

NightClub can use a file monitor to steal specific files from targeted systems.

### S0352 - OSX_OCEANLOTUS.D

OSX_OCEANLOTUS.D has the ability to upload files from a compromised host.

### S0340 - Octopus

Octopus can exfiltrate files from the system using a documents collector tool.

### S0594 - Out1

Out1 can copy files and Registry data from compromised hosts.

### S1017 - OutSteel

OutSteel can collect information from a compromised host.

### S0598 - P.A.S. Webshell

P.A.S. Webshell has the ability to copy files on a compromised host.

### S0223 - POWERSTATS

POWERSTATS can upload files from compromised hosts.

### S0197 - PUNCHTRACK

PUNCHTRACK scrapes memory for properly formatted payment card data.

### S0208 - Pasam

Pasam creates a backdoor through which remote attackers can retrieve files.

### S1050 - PcShare

PcShare can collect files and information from a compromised host.

### S1102 - Pcexter

Pcexter can upload files from targeted systems.

### S0517 - Pillowmint

Pillowmint has collected credit card data using native API functions.

### S0048 - PinchDuke

PinchDuke collects user files from the compromised host based on predefined file extensions.

### S1031 - PingPull

PingPull can collect data from a compromised host.

### S0012 - PoisonIvy

PoisonIvy creates a backdoor through which remote attackers can steal system information.

### S1012 - PowerLess

PowerLess has the ability to exfiltrate data, including Chrome and Edge browser database files, from compromised machines.

### S0194 - PowerSploit

PowerSploit contains a collection of Exfiltration modules that can access data from local files, volumes, and processes.

### S0238 - Proxysvc

Proxysvc searches the local system and gathers data.

### S0650 - QakBot

QakBot can use a variety of commands, including esentutl.exe to steal sensitive data from Internet Explorer and Microsoft Edge, to acquire information that is subsequently exfiltrated.

### S0262 - QuasarRAT

QuasarRAT can retrieve files from compromised client machines.

### S0686 - QuietSieve

QuietSieve can collect files from a compromised host.

### S1113 - RAPIDPULSE

RAPIDPULSE retrieves files from the victim system via encrypted commands sent to the web shell.

### S0662 - RCSession

RCSession can collect data from a compromised host.

### S0240 - ROKRAT

ROKRAT can collect host data and specific file types.

### S1148 - Raccoon Stealer

Raccoon Stealer collects data from victim machines based on configuration information received from command and control nodes.

### S0629 - RainyDay

RainyDay can use a file exfiltration tool to collect recently changed files on a compromised host.

### S0458 - Ramsay

Ramsay can collect Microsoft Word documents from the target's file system, as well as <code>.txt</code>, <code>.doc</code>, and <code>.xls</code> files from the Internet Explorer cache.

### S0169 - RawPOS

RawPOS dumps memory from specific processes on a victim system, parses the dumped files, and scrapes them for credit card data.

### S1240 - RedLine Stealer

RedLine Stealer has collected data stored locally including chat logs and files associated with chat services such as Steam, Discord, and Telegram.

### S0448 - Rising Sun

Rising Sun has collected data and files from a compromised host.

### S0090 - Rover

Rover searches for files on local drives based on a predefined list of file extensions.

### S0461 - SDBbot

SDBbot has the ability to access the file system on a compromised host.

### S1110 - SLIGHTPULSE

SLIGHTPULSE can read files specified on the local system.

### S0533 - SLOTHFULMEDIA

SLOTHFULMEDIA has uploaded files and information from victim machines.

### S1037 - STARWHALE

STARWHALE can collect data from an infected local host.

### S0559 - SUNBURST

SUNBURST collected information from a compromised host.

### S1064 - SVCReady

SVCReady can collect data from an infected host.

### S1018 - Saint Bot

Saint Bot can collect files and information from a compromised host.

### S1099 - Samurai

Samurai can leverage an exfiltration module to download arbitrary files from compromised machines.

### S1085 - Sardonic

Sardonic has the ability to collect data from a compromised machine to deliver to the attacker.

### S1019 - Shark

Shark can upload files to its C2.

### S1089 - SharpDisco

SharpDisco has dropped a recent-files stealer plugin to `C:\Users\Public\WinSrcNT\It11.exe`.

### S0444 - ShimRat

ShimRat has the capability to upload collected files to a C2.

### S0610 - SideTwist

SideTwist has the ability to upload files from a compromised host.

### S0615 - SombRAT

SombRAT has collected data and files from a compromised host.

### S0646 - SpicyOmelette

SpicyOmelette has collected data and other information from a compromised host.

### S1200 - StealBit

StealBit can upload data and files to the LockBit victim-shaming site.

### S1034 - StrifeWater

StrifeWater can collect data from a compromised host.

### S0663 - SysUpdate

SysUpdate can collect information and files from a compromised host.

### S0011 - Taidoor

Taidoor can upload data and files from a victim's machine.

### S0467 - TajMahal

TajMahal has the ability to steal documents from the local system including the print spooler queue.

### S0665 - ThreatNeedle

ThreatNeedle can collect data and files from a compromised host.

### S0668 - TinyTurla

TinyTurla can upload files from a compromised host.

### S0671 - Tomiris

Tomiris has the ability to collect recent files matching a hardcoded list of extensions prior to exfiltration.

### S0266 - TrickBot

TrickBot collects local files and information from the victim’s local machine.

### S1196 - Troll Stealer

Troll Stealer gathers information from infected systems such as SSH information from the victim's `.ssh` directory. Troll Stealer collects information from local FileZilla installations and Microsoft Sticky Note.

### S0452 - USBferry

USBferry can collect information from an air-gapped host machine.

### S0022 - Uroburos

Uroburos can use its `Get` command to exfiltrate specified files from the compromised system.

### S0386 - Ursnif

Ursnif has collected files from victim machines, including certificates and cookies.

### S0670 - WarzoneRAT

WarzoneRAT can collect data from a compromised host.

### S0515 - WellMail

WellMail can exfiltrate files from the victim machine.

### S0514 - WellMess

WellMess can send files from the victim machine to C2.

### S0645 - Wevtutil

Wevtutil can be used to export events from a specific log.

### S1065 - Woody RAT

Woody RAT can collect information from a compromised host.

### S0658 - XCSSET

XCSSET collects contacts and application data from files in Desktop, Documents, Downloads, Dropbox, and WeChat folders.

### S0672 - Zox

Zox has the ability to upload files from a targeted system.

### S0412 - ZxShell

ZxShell can transfer files from a compromised host.

### S1013 - ZxxZ

ZxxZ can collect data from a compromised host.

### S1043 - ccf32

ccf32 can collect files from a compromised host.

### S0404 - esentutl

esentutl can be used to collect data from local file systems.

### S1059 - metaMain

metaMain can collect files and system information from a compromised host.

### S0385 - njRAT

njRAT can collect data from a local system.

### S0653 - xCaon

xCaon has uploaded files from victims' machines.

### S0248 - yty

yty collects files with the following extensions: .ppt, .pptx, .pdf, .doc, .docx, .xls, .xlsx, .docm, .rtf, .inp, .xlsm, .csv, .odt, .pps, .vcf and sends them back to the C2 server.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0015 - C0015

During C0015, the threat actors obtained files and data from the compromised network.

### C0017 - C0017

During C0017, APT41 collected information related to compromised machines as well as Personal Identifiable Information (PII) from victim networks.

### C0026 - C0026

During C0026, the threat actors collected documents from compromised hosts.

### C0004 - CostaRicto

During CostaRicto, the threat actors collected data and files from compromised networks.

### C0029 - Cutting Edge

During Cutting Edge, threat actors stole the running configuration and cache data from targeted Ivanti Connect Secure VPNs.

### C0001 - Frankenstein

During Frankenstein, the threat actors used Empire to gather various local system information.

### C0002 - Night Dragon

During Night Dragon, the threat actors collected files and other data from compromised systems.

### C0012 - Operation CuckooBees

During Operation CuckooBees, the threat actors collected data, files, and other information from compromised networks.

### C0022 - Operation Dream Job

During Operation Dream Job, Lazarus Group used malicious Trojans and DLL files to exfiltrate data from an infected host.

### C0006 - Operation Honeybee

During Operation Honeybee, the threat actors collected data from compromised hosts.

### C0048 - Operation MidnightEclipse

During Operation MidnightEclipse, threat actors stole saved cookies and login data from targeted systems.

### C0014 - Operation Wocao

During Operation Wocao, threat actors exfiltrated files and directories of interest from the targeted system.

### C0058 - SharePoint ToolShell Exploitation

During SharePoint ToolShell Exploitation, threat actors extracted information from the compromised systems.

### C0024 - SolarWinds Compromise

During the SolarWinds Compromise, APT29 extracted files from compromised networks.
