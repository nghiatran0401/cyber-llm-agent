# T1041 - Exfiltration Over C2 Channel

**Tactic:** Exfiltration
**Platforms:** ESXi, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1041

## Description

Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.

## Detection

### Detection Analytics

**Analytic 0988**

Identifies suspicious outbound traffic volume mismatches from processes that typically do not generate network activity, particularly over C2 protocols like HTTPS, DNS, or custom TCP/UDP ports, following file or data access.

**Analytic 0989**

Monitors for processes reading sensitive files then immediately initiating unusual outbound connections or bulk transfer sessions over persistent sockets, particularly with encrypted or binary payloads.

**Analytic 0990**

Detects unauthorized applications or scripts accessing sensitive data followed by establishing encrypted outbound communication to rare external destinations or with abnormal byte ratios.

**Analytic 0991**

Detects VMs sending outbound traffic through non-standard services or to unknown destinations. Exfiltration over reverse shells tunneled via VMkernel or custom payloads routed via hostd/vpxa.


## Mitigations

### M1057 - Data Loss Prevention

Data loss prevention can detect and block sensitive data being sent over unencrypted protocols.

### M1031 - Network Intrusion Prevention

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool command and control signatures over time or construct protocols in such a way to avoid detection by common defensive tools.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0045 - ADVSTORESHELL

ADVSTORESHELL exfiltrates data over the same channel used for C2.

### S1025 - Amadey

Amadey has sent victim data to its C2 servers.

### S0584 - AppleJeus

AppleJeus has exfiltrated collected host information to a C2 server.

### S0622 - AppleSeed

AppleSeed can exfiltrate files via the C2 channel.

### S0373 - Astaroth

Astaroth exfiltrates collected information from its r1.log file to the external C2 server.

### S0438 - Attor

Attor has exfiltrated data over the C2 channel.

### S1029 - AuTo Stealer

AuTo Stealer can exfiltrate data over actor-controlled C2 servers via HTTP or TCP.

### S0031 - BACKSPACE

Adversaries can direct BACKSPACE to upload files to the C2 Server.

### S1081 - BADHATCH

BADHATCH can exfiltrate data over the C2 channel.

### S0520 - BLINDINGCAN

BLINDINGCAN has sent user and system information to a C2 server via HTTP POST requests.

### S0657 - BLUELIGHT

BLUELIGHT has exfiltrated data over its C2 channel.

### S0234 - Bandook

Bandook can upload files from a victim's machine over the C2 channel.

### S0239 - Bankshot

Bankshot exfiltrates data over its C2 channel.

### S1246 - BeaverTail

BeaverTail has exfiltrated data collected from victim devices to C2 servers.

### S0268 - Bisonal

Bisonal has added the exfiltrated data to the URL over the C2 channel.

### S0651 - BoxCaon

BoxCaon uploads files and data from a compromised host over the existing C2 channel.

### S1039 - Bumblebee

Bumblebee can send collected data in JSON format to C2.

### S1149 - CHIMNEYSWEEP

CHIMNEYSWEEP  can upload collected files to the command-and-control server.

### S0077 - CallMe

CallMe exfiltrates data to its C2 server over the same protocol as C2 communications.

### S0351 - Cannon

Cannon exfiltrates collected data over email via SMTP/S and POP3/S C2 channels.

### S0484 - Carberp

Carberp has exfiltrated data via HTTP to already established C2 servers.

### S0572 - Caterpillar WebShell

Caterpillar WebShell can upload files over the C2 channel.

### S0674 - CharmPower

CharmPower can exfiltrate gathered data to a hardcoded C2 URL via HTTP POST.

### S0667 - Chrommme

Chrommme can exfiltrate collected data via C2.

### S1024 - CreepySnail

CreepySnail can connect to C2 for data exfiltration.

### S0115 - Crimson

Crimson can exfiltrate stolen information over its C2.

### S0538 - Crutch

Crutch can exfiltrate data over the primary C2 channel (Dropbox HTTP API).

### S1153 - Cuckoo Stealer

Cuckoo Stealer can send information about the targeted system to C2 including captured passwords, OS build, hostname, and username.

### S0687 - Cyclops Blink

Cyclops Blink has the ability to upload exfiltrated files to a C2 server.

### S1159 - DUSTTRAP

DUSTTRAP can exfiltrate collected data over C2 channels.

### S1111 - DarkGate

DarkGate uses existing command and control channels to retrieve captured cryptocurrency wallet credentials.

### S1021 - DnsSystem

DnsSystem can exfiltrate collected data to its C2 server.

### S0600 - Doki

Doki has used Ngrok to establish C2 and exfiltrate data.

### S0502 - Drovorub

Drovorub can exfiltrate files over C2 infrastructure.

### S0062 - DustySky

DustySky has exfiltrated data to the C2 server.

### S0024 - Dyre

Dyre has the ability to send information staged on a compromised host externally to C2.

### S0568 - EVILNUM

EVILNUM can upload files over the C2 channel from the infected host.

### S0377 - Ebury

Ebury exfiltrates a list of outbound and inbound SSH sessions using OpenSSH's `known_host` files and `wtmp` records. Ebury can exfiltrate SSH credentials through custom DNS queries or use the command `Xcat` to send the process's ssh session's credentials to the C2 server.

### S0367 - Emotet

Emotet has exfiltrated data over its C2 channel.

### S0363 - Empire

Empire can send data gathered from a target through the command and control channel.

### S0696 - Flagpro

Flagpro has exfiltrated data to the C2 server.

### S0381 - FlawedAmmyy

FlawedAmmyy has sent data collected from a compromised host to its C2 servers.

### S0661 - FoggyWeb

FoggyWeb can remotely exfiltrate sensitive information from a compromised AD FS server.

### S1044 - FunnyDream

FunnyDream can execute commands, including gathering user information, and send the results to C2.

### S0588 - GoldMax

GoldMax can exfiltrate files over the existing C2 channel.

### S0493 - GoldenSpy

GoldenSpy has exfiltrated host environment information to an external C2 domain via port 9006.

### S0477 - Goopy

Goopy has the ability to exfiltrate data over the Microsoft Outlook C2 channel.

### S0531 - Grandoreiro

Grandoreiro can send data it retrieves to the C2 server.

### S0632 - GrimAgent

GrimAgent has sent data related to a compromise host over its C2 channel.

### S0391 - HAWKBALL

HAWKBALL has sent system information and files over the C2 channel.

### S0376 - HOPLIGHT

HOPLIGHT has used its C2 channel to exfiltrate data.

### S1249 - HexEval Loader

HexEval Loader has exfiltrated victim data using HTTPS POST requests to its C2 servers.

### S0431 - HotCroissant

HotCroissant has the ability to download files from the infected host to the command and control (C2) server.

### S1132 - IPsec Helper

IPsec Helper exfiltrates specific files through its command and control framework.

### S1022 - IceApple

IceApple's Multi File Exfiltrator module can exfiltrate multiple files from a compromised host as an HTTP response over C2.

### S0434 - Imminent Monitor

Imminent Monitor has uploaded a file containing debugger logs, network information and system information to the C2.

### S0604 - Industroyer

Industroyer sends information about hardware profiles and previously-received commands back to the C2 server in a POST-request.

### S1245 - InvisibleFerret

InvisibleFerret has used HTTP communications to the “/Uploads” URI for file exfiltration.

### S0526 - KGH_SPY

KGH_SPY can exfiltrate collected information from the host to the C2 server.

### S0356 - KONNI

KONNI has sent data and files to its C2 server.

### S1075 - KOPILUWAK

KOPILUWAK has exfiltrated collected data to its C2 via POST requests.

### S0487 - Kessel

Kessel has exfiltrated information gathered from the infected system to the C2 server.

### S1020 - Kevin

Kevin can send data from the victim host through a DNS C2 channel.

### S1160 - Latrodectus

Latrodectus can exfiltrate encrypted system information to the C2 server.

### S0395 - LightNeuron

LightNeuron exfiltrates data over its email C2 channel.

### S1185 - LightSpy

To exfiltrate data, LightSpy configures each module to send an obfuscated JSON blob to hardcoded URL endpoints or paths aligned to the module name.

### S1186 - Line Dancer

Line Dancer exfiltrates collected data via command and control channels.

### S1188 - Line Runner

Line Runner utilizes HTTP to retrieve and exfiltrate information staged using Line Dancer.

### S0680 - LitePower

LitePower can send collected data, including screenshots, over its C2 channel.

### S0447 - Lokibot

Lokibot has the ability to initiate contact with command and control (C2) to exfiltrate stolen data.

### S1213 - Lumma Stealer

Lumma Stealer has exfiltrated collected data over existing HTTP and HTTPS C2 channels.

### S1142 - LunarMail

LunarMail can use email image attachments with embedded data for receiving C2 commands and data exfiltration.

### S1016 - MacMa

MacMa exfiltrates data from a supplied path over its C2 channel.

### S0409 - Machete

Machete's collected data is exfiltrated over the same channel used for C2.

### S1060 - Mafalda

Mafalda can send network system data and files to its C2 server.

### S1182 - MagicRAT

MagicRAT exfiltrates data via HTTP over existing command and control channels.

### S1169 - Mango

Mango can use its HTTP C2 channel for exfiltration.

### S1156 - Manjusaka

Manjusaka data exfiltration takes place over HTTP channels.

### S0652 - MarkiRAT

MarkiRAT can exfiltrate locally stored data via its C2.

### S0459 - MechaFlounder

MechaFlounder has the ability to send the compromised user's account name and hostname within a URL to C2.

### S0455 - Metamorfo

Metamorfo can send the data it collects to the C2 server.

### S0084 - Mis-Type

Mis-Type has transmitted collected files and data to its C2 server.

### S0083 - Misdat

Misdat has uploaded files and data to its C2 servers.

### S1122 - Mispadu

Mispadu can sends the collected financial data to the C2 server.

### S0079 - MobileOrder

MobileOrder exfiltrates data to its C2 server over the same protocol as C2 communications.

### S1026 - Mongall

Mongall can upload files and information from a compromised host to its C2 server.

### S0034 - NETEAGLE

NETEAGLE is capable of reading files over the C2 channel.

### S1090 - NightClub

NightClub can use SMTP and DNS for file exfiltration and C2.

### S1170 - ODAgent

ODAgent can use an attacker-controlled OneDrive account to receive C2 commands and to exfiltrate files.

### S0340 - Octopus

Octopus has uploaded stolen files and data from a victim's machine over its C2 channel.

### S1172 - OilBooster

OilBooster can use an actor-controlled OneDrive account for C2 communication and exfiltration.

### S0439 - Okrum

Data exfiltration is done by Okrum using the already opened channel with the C2 server.

### S0264 - OopsIE

OopsIE can upload files from the victim's machine to its C2 server.

### S1017 - OutSteel

OutSteel can upload files from a compromised host over its C2 channel.

### S1050 - PcShare

PcShare can upload files and information from a compromised host to its C2 servers.

### S0587 - Penquin

Penquin can execute the command code <code>do_upload</code> to send files to C2.

### S1145 - Pikabot

During the initial Pikabot command and control check-in, Pikabot will transmit collected system information encrypted using RC4.

### S1031 - PingPull

PingPull has the ability to exfiltrate stolen victim data through its C2 channel.

### S0013 - PlugX

PlugX has exfiltrated stolen data and files to its C2 server.

### S0428 - PoetRAT

PoetRAT has exfiltrated data over the C2 channel.

### S1173 - PowerExchange

PowerExchange can exfiltrate files via its email C2 channel.

### S0441 - PowerShower

PowerShower has used a PowerShell document stealer module to pack and exfiltrate .txt, .pdf, .xls or .doc files smaller than 5MB that were modified during the past two days.

### S0238 - Proxysvc

Proxysvc performs data exfiltration over the control server channel using a custom protocol.

### S0078 - Psylo

Psylo exfiltrates data to its C2 server over the same protocol as C2 communications.

### S0147 - Pteranodon

Pteranodon exfiltrates screenshot files to its C2 server.

### S0192 - Pupy

Pupy can send screenshots files, keylogger data, files, and recorded audio back to the C2 server.

### S0650 - QakBot

QakBot can send stolen information to C2 nodes including passwords, accounts, and emails.

### S0495 - RDAT

RDAT can exfiltrate data gathered from the infected system via the established Exchange Web Services API C2 channel.

### S0496 - REvil

REvil can exfiltrate host and malware information to C2 servers.

### S0240 - ROKRAT

ROKRAT can send collected files back over same C2 channel.

### S1148 - Raccoon Stealer

Raccoon Stealer uses existing HTTP-based command and control channels for exfiltration.

### S1240 - RedLine Stealer

RedLine Stealer has sent victim data to its C2 server or RedLine panel server.

### S0375 - Remexi

Remexi performs exfiltration over BITSAdmin, which is also used for the C2 channel.

### S0448 - Rising Sun

Rising Sun can send data gathered from the infected machine via HTTP POST request to the C2.

### S1078 - RotaJakiro

RotaJakiro sends device and other collected data back to the C2 using the established C2 channels over TCP.

### S0085 - S-Type

S-Type has uploaded data and files from a compromised host to its C2 servers.

### S0461 - SDBbot

SDBbot has sent collected data from a compromised host to its C2 servers.

### S0692 - SILENTTRINITY

SILENTTRINITY can transfer files from an infected host to the C2 server.

### S0533 - SLOTHFULMEDIA

SLOTHFULMEDIA has sent system information to a C2 server via HTTP and HTTPS POST requests.

### S0649 - SMOKEDHAM

SMOKEDHAM has exfiltrated data to its C2 server.

### S1037 - STARWHALE

STARWHALE can exfiltrate collected data to its C2 servers.

### S1042 - SUGARDUMP

SUGARDUMP has sent stolen credentials and other data to its C2 server.

### S1064 - SVCReady

SVCReady can send collected data in JSON format to its C2 server.

### S1210 - Sagerunex

Sagerunex encrypts collected system data then exfiltrates via existing command and control channels.

### S1019 - Shark

Shark has the ability to upload files from the compromised host over a DNS or HTTP C2 channel.

### S1089 - SharpDisco

SharpDisco can load a plugin to exfiltrate stolen files to SMB shares also used in C2.

### S0445 - ShimRatReporter

ShimRatReporter sent generated reports to the C2 via HTTP POST requests.

### S1178 - ShrinkLocker

ShrinkLocker will exfiltrate victim system information along with the encryption key via an HTTP POST.

### S0610 - SideTwist

SideTwist has exfiltrated data over its C2 channel.

### S0633 - Sliver

Sliver can exfiltrate files from the victim using the <code>download</code> command.

### S1166 - Solar

Solar can send staged files to C2 for exfiltration.

### S0615 - SombRAT

SombRAT has uploaded collected data and files from a compromised host to its C2 server.

### S0543 - Spark

Spark has exfiltrated data over the C2 channel.

### S1030 - Squirrelwaffle

Squirrelwaffle has exfiltrated victim data using HTTP POST requests to its C2 servers.

### S1183 - StrelaStealer

StrelaStealer exfiltrates collected email credentials via HTTP POST to command and control servers.

### S1034 - StrifeWater

StrifeWater can send data and files from a compromised host to its C2 server.

### S0491 - StrongPity

StrongPity can exfiltrate collected documents through C2 channels.

### S0603 - Stuxnet

Stuxnet sends compromised victim information via HTTP.

### S0663 - SysUpdate

SysUpdate has exfiltrated data over its C2 channel.

### S1201 - TRANSLATEXT

TRANSLATEXT has exfiltrated collected credentials to the C2 server.

### S0467 - TajMahal

TajMahal has the ability to send collected files over its C2.

### S0595 - ThiefQuest

ThiefQuest exfiltrates targeted file extensions in the <code>/Users/</code> folder to the command and control server via unencrypted HTTP. Network packets contain a string with two pieces of information: a file path and the contents of the file in a base64 encoded string.

### S0671 - Tomiris

Tomiris can upload files matching a hardcoded set of extensions, such as .doc, .docx, .pdf, and .rar, to its C2 server.

### S0678 - Torisma

Torisma can send victim data to an actor-controlled C2 server.

### S0266 - TrickBot

TrickBot can send information about the compromised host and upload data to a hardcoded C2 server.

### S1196 - Troll Stealer

Troll Stealer exfiltrates collected information to its command and control infrastructure.

### S0386 - Ursnif

Ursnif has used HTTP POSTs to exfil gathered information.

### S0476 - Valak

Valak has the ability to exfiltrate data over the C2 channel.

### S0670 - WarzoneRAT

WarzoneRAT can send collected victim data to its C2 server.

### S1065 - Woody RAT

Woody RAT can exfiltrate files from an infected machine to its C2 server.

### S0658 - XCSSET

XCSSET retrieves files that match the pattern defined in the INAME_QUERY variable within the user's home directory, such as `*test.txt`, and are below a specific size limit. It then archives the files and exfiltrates the data over its C2 channel.

### S1248 - XORIndex Loader

XORIndex Loader has exfiltrated victim data using HTTPS POST requests to its C2 servers.

### S0086 - ZLib

ZLib has sent data and files from a compromised host to its C2 servers.

### S0251 - Zebrocy

Zebrocy has exfiltrated data to the designated C2 server using HTTP POST requests.

### S1059 - metaMain

metaMain can upload collected files and data to its C2 server.

### S0385 - njRAT

njRAT has used HTTP to receive stolen information from the infected machine.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0046 - ArcaneDoor

ArcaneDoor included use of existing command and control channels for data exfiltration.

### C0017 - C0017

During C0017, APT41 used its Cloudflare services C2 channels for data exfiltration.

### C0001 - Frankenstein

During Frankenstein, the threat actors collected information via Empire, which sent the data back to the adversary's C2.

### C0038 - HomeLand Justice

During HomeLand Justice, threat actors used HTTP to transfer data from compromised Exchange servers.

### C0049 - Leviathan Australian Intrusions

Leviathan exfiltrated collected data over existing command and control channels during Leviathan Australian Intrusions.

### C0022 - Operation Dream Job

During Operation Dream Job, Lazarus Group exfiltrated data from a compromised host to actor-controlled C2 servers.

### C0006 - Operation Honeybee

During Operation Honeybee, the threat actors uploaded stolen files to their C2 servers.

### C0014 - Operation Wocao

During Operation Wocao, threat actors used the XServer backdoor to exfiltrate data.

### C0056 - RedPenguin

During RedPenguin, UNC3886 uploaded specified files from compromised devices to a remote server.

### C0058 - SharePoint ToolShell Exploitation

During SharePoint ToolShell Exploitation, threat actors exfiltrated stolen credentials and internal data over HTTPS to C2 infrastructure.
