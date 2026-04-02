# T1033 - System Owner/User Discovery

**Tactic:** Discovery
**Platforms:** Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1033

## Description

Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using OS Credential Dumping. The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs. Adversaries may use the information from System Owner/User Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Various utilities and commands may acquire this information, including <code>whoami</code>. In macOS and Linux, the currently logged in user can be identified with <code>w</code> and <code>who</code>. On macOS the <code>dscl . list /Users | grep -v '_'</code> command can also be used to enumerate user accounts. Environment variables, such as <code>%USERNAME%</code> and <code>$USER</code>, may also be used to access this information.

On network devices, Network Device CLI commands such as `show users` and `show ssh` can be used to display users currently logged into the device.

## Detection

### Detection Analytics

**Analytic 0254**

Adversary launches built-in system tools (e.g., whoami, query user, net user) or scripts that enumerate user account information via local execution or remote API queries (e.g., WMI, PowerShell).

**Analytic 0255**

Adversary runs commands like `whoami`, `id`, `w`, or `cat /etc/passwd` from non-interactive or scripting contexts to enumerate system user details.

**Analytic 0256**

Adversary uses `dscl`, `who`, or environment variables like `$USER` to identify accounts or sessions via Terminal or malicious LaunchAgents.

**Analytic 0257**

Adversary executes CLI commands like `show users`, `show ssh`, or attempts to dump AAA user lists from routers or switches.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1028 - Action RAT

Action RAT has the ability to collect the username from an infected host.

### S0331 - Agent Tesla

Agent Tesla can collect the username from the victim’s machine.

### S0092 - Agent.btz

Agent.btz obtains the victim username and saves it to a file.

### S1025 - Amadey

Amadey has collected the user name from a compromised host using `GetUserNameA`.

### S0456 - Aria-body

Aria-body has the ability to identify the username on a compromised host.

### S1087 - AsyncRAT

AsyncRAT can check if the current user of a compromised system is an administrator.

### S1029 - AuTo Stealer

AuTo Stealer has the ability to collect the username from an infected host.

### S0344 - Azorult

Azorult can collect the username from the victim’s machine.

### S1081 - BADHATCH

BADHATCH can obtain logged user information from a compromised machine and can execute the command `whoami.exe`.

### S0017 - BISCUIT

BISCUIT has a command to gather the username from the system.

### S0657 - BLUELIGHT

BLUELIGHT can collect the username on a compromised host.

### S1226 - BOOKWORM

BOOKWORM has obtained the username from an infected host.

### S0414 - BabyShark

BabyShark has executed the <code>whoami</code> command.

### S0093 - Backdoor.Oldrea

Backdoor.Oldrea collects the current username from the victim.

### S0534 - Bazar

Bazar can identify the username of the infected user.

### S1068 - BlackCat

BlackCat can utilize `net use` commands to discover the user name on a compromised host.

### S0521 - BloodHound

BloodHound can collect information on user sessions.

### S0486 - Bonadan

Bonadan has discovered the username of the user running the backdoor.

### S0635 - BoomBox

BoomBox can enumerate the username on a compromised host.

### S1039 - Bumblebee

Bumblebee has the ability to identify the user name.

### S1149 - CHIMNEYSWEEP

CHIMNEYSWEEP has included the victim's computer name and username in C2 messages sent to actor-owned infrastructure.

### S0351 - Cannon

Cannon can gather the username from the system.

### S0348 - Cardinal RAT

Cardinal RAT can collect the username from a victim machine.

### S0572 - Caterpillar WebShell

Caterpillar WebShell can obtain a list of user accounts from a victim's machine.

### S0631 - Chaes

Chaes has collected the username and UID from the infected machine.

### S0667 - Chrommme

Chrommme can retrieve the username from a targeted system.

### S0660 - Clambling

Clambling can identify the username on a compromised host.

### S1024 - CreepySnail

CreepySnail can execute `getUsername` on compromised systems.

### S0115 - Crimson

Crimson can identify the user on a targeted system.

### S0498 - Cryptoistic

Cryptoistic can gather data on the user of a compromised host.

### S1153 - Cuckoo Stealer

Cuckoo Stealer can discover and send the username from a compromised host to C2.

### S0694 - DRATzarus

DRATzarus can obtain a list of users from an infected machine.

### S0334 - DarkComet

DarkComet gathers the username from the victim’s machine.

### S0673 - DarkWatchman

DarkWatchman has collected the username from a victim machine.

### S0354 - Denis

Denis enumerates and collects the username from the victim’s machine.

### S0021 - Derusbi

A Linux version of Derusbi checks if the victim user ID is anything other than zero (normally used for root), and the malware will not execute if it does not have root privileges. Derusbi also gathers the username of the victim.

### S0659 - Diavol

Diavol can collect the username from a compromised host.

### S1021 - DnsSystem

DnsSystem can use the Windows user name to create a unique identification for infected users and systems.

### S0186 - DownPaper

DownPaper collects the victim username and sends it to the C2 server.

### S0024 - Dyre

Dyre has the ability to identify the users on a compromised host.

### S0568 - EVILNUM

EVILNUM can obtain the username from the victim's machine.

### S0554 - Egregor

Egregor has used tools to gather information about users.

### S0367 - Emotet

Emotet has enumerated all users connected to network shares.

### S0363 - Empire

Empire can enumerate the username on targeted hosts.

### S0091 - Epic

Epic collects the user name from the victim’s machine.

### S0401 - Exaramel for Linux

Exaramel for Linux can run <code>whoami</code> to identify the system owner.

### S0569 - Explosive

Explosive has collected the username from the infected host.

### S0267 - FELIXROOT

FELIXROOT collects the username from the victim’s machine.

### S0171 - Felismus

Felismus collects the current username and sends it to the C2 server.

### S0696 - Flagpro

Flagpro has been used to run the <code>whoami</code> command on the system.

### S0381 - FlawedAmmyy

FlawedAmmyy enumerates the current user during the initial infection.

### S1044 - FunnyDream

FunnyDream has the ability to gather user information from the targeted system using `whoami/upn&whoami/fqdn&whoami/logonid&whoami/all`.

### S0168 - Gazer

Gazer obtains the current user's security identifier.

### S0666 - Gelsemium

Gelsemium has the ability to distinguish between a standard user and an administrator on a compromised host.

### S0460 - Get2

Get2 has the ability to identify the current username of an infected host.

### S0249 - Gold Dragon

Gold Dragon collects the endpoint victim's username and uses it as a basis for downloading additional components from the C2 server.

### S0477 - Goopy

Goopy has the ability to enumerate the infected system's user name.

### S0531 - Grandoreiro

Grandoreiro can collect the username from the victim's machine.

### S0237 - GravityRAT

GravityRAT collects the victim username along with other account information (account type, description, full name, SID and status).

### S0632 - GrimAgent

GrimAgent can identify the user id on a target machine.

### S0214 - HAPPYWORK

can collect the victim user name.

### S0391 - HAWKBALL

HAWKBALL can collect the user name of the system.

### S1229 - Havoc

Havoc can trigger exection of `whoami` on the target host to display the current user.

### S1249 - HexEval Loader

HexEval Loader has collected the username from the victim host.

### S0431 - HotCroissant

HotCroissant has the ability to collect the username on the infected host.

### S0260 - InvisiMole

InvisiMole lists local users and session information.

### S1245 - InvisibleFerret

InvisibleFerret has identified the user’s UUID and username through the "pay" module.

### S0015 - Ixeshe

Ixeshe collects the username from the victim’s machine.

### S0201 - JPIN

JPIN can obtain the victim user name.

### S0356 - KONNI

KONNI can collect the username from the victim’s machine.

### S1075 - KOPILUWAK

KOPILUWAK can conduct basic network reconnaissance on the victim machine with `whoami`, to get user details.

### S0265 - Kazuar

Kazuar gathers information on users.

### S0250 - Koadic

Koadic can identify logged in users across the domain and views user sessions.

### S0162 - Komplex

The OsInfo function in Komplex collects the current running username.

### S0236 - Kwampirs

Kwampirs collects registered owner details by using the commands <code>systeminfo</code> and <code>net config workstation</code>.

### S1160 - Latrodectus

Latrodectus can discover the username of an infected host.

### S0362 - Linux Rabbit

Linux Rabbit opens a socket on port 22 and if it receives a response it attempts to obtain the machine's hostname and Top-Level Domain.

### S0513 - LiteDuke

LiteDuke can enumerate the account name on a targeted system.

### S0680 - LitePower

LitePower can determine if the current user has admin privileges.

### S0681 - Lizar

Lizar can collect the username from the system.

### S0447 - Lokibot

Lokibot has the ability to discover the username on the infected host.

### S0532 - Lucifer

Lucifer has the ability to identify the username on a compromised host.

### S1141 - LunarWeb

LunarWeb can collect user information from the targeted host.

### S1016 - MacMa

MacMa can collect the username from the compromised machine.

### S1060 - Mafalda

Mafalda can collect the username from a compromised host.

### S1169 - Mango

Mango can collect the user name from a compromised system which is used to create a unique victim identifier.

### S0652 - MarkiRAT

MarkiRAT can retrieve the victim’s username.

### S0459 - MechaFlounder

MechaFlounder has the ability to identify the username and hostname on a compromised host.

### S0455 - Metamorfo

Metamorfo has collected the username from the victim's machine.

### S1146 - MgBot

MgBot includes modules for identifying local users and administrators on victim machines.

### S0339 - Micropsia

Micropsia collects the username from the victim’s machine.

### S1015 - Milan

Milan can identify users registered to a targeted machine.

### S0280 - MirageFox

MirageFox can gather the username from the victim’s machine.

### S0084 - Mis-Type

Mis-Type runs tests to determine the privilege level of the compromised user.

### S0149 - MoonWind

MoonWind obtains the victim username.

### S0284 - More_eggs

More_eggs has the capability to gather the username from the victim's machine.

### S0256 - Mosquito

Mosquito runs <code>whoami</code> on the victim’s machine.

### S0590 - NBTscan

NBTscan can list active users on the system.

### S0272 - NDiskMonitor

NDiskMonitor obtains the victim username and encrypts the information to send over its C2 channel.

### S1106 - NGLite

NGLite will run the <code>whoami</code> command to gather system information and return this to the command and control server.

### S0353 - NOKKI

NOKKI can collect the username from the victim’s machine.

### S0228 - NanHaiShu

NanHaiShu collects the username from the victim.

### S0691 - Neoichor

Neoichor can collect the user name from a victim's machine.

### S1147 - Nightdoor

Nightdoor gathers information on victim system users and usernames.

### S0644 - ObliqueRAT

ObliqueRAT can check for blocklisted usernames on infected endpoints.

### S0340 - Octopus

Octopus can collect the username from the victim’s machine.

### S1172 - OilBooster

OilBooster can identify the compromised system's username which is then used as part of a unique identifier.

### S0439 - Okrum

Okrum can collect the victim username.

### S0223 - POWERSTATS

POWERSTATS has the ability to identify the username on the compromised host.

### S0184 - POWRUNER

POWRUNER may collect information about the currently logged in user by running <code>whoami</code> on a victim.

### S1228 - PUBLOAD

PUBLOAD has obtained the username from an infected host.

### S0013 - PlugX

PlugX has the ability to gather the username from the victim’s machine.

### S0428 - PoetRAT

PoetRAT sent username, computer name, and the previously generated UUID in reply to a "who" command from C2.

### S0139 - PowerDuke

PowerDuke has commands to get the current user's name and SID.

### S0441 - PowerShower

PowerShower has the ability to identify the current user on the infected host.

### S0113 - Prikormka

A module in Prikormka collects information from the victim about the current user name.

### S0192 - Pupy

Pupy can enumerate local information for Linux hosts and find currently logged on users for Windows hosts.

### S1032 - PyDCrypt

PyDCrypt has probed victim machines with <code>whoami</code> and has collected the username from the machine.

### S0269 - QUADAGENT

QUADAGENT gathers the victim username.

### S0650 - QakBot

QakBot can identify the user name on a compromised system.

### S0262 - QuasarRAT

QuasarRAT can enumerate the username and account type.

### S0241 - RATANKBA

RATANKBA runs the <code>whoami</code> and <code>query user</code> commands.

### S0662 - RCSession

RCSession can gather system owner information, including user and administrator privileges.

### S0258 - RGDoor

RGDoor executes the <code>whoami</code> on the victim’s machine.

### S0240 - ROKRAT

ROKRAT can collect the username from a compromised host.

### S0148 - RTM

RTM can obtain the victim username and permissions.

### S1148 - Raccoon Stealer

Raccoon Stealer gathers information on the infected system owner and user.

### S1130 - Raspberry Robin

Raspberry Robin determines whether it is successfully running on a victim system by querying the running account information to determine if it is running in Session 0, indicating running with elevated privileges.

### S0172 - Reaver

Reaver collects the victim's username.

### S0153 - RedLeaves

RedLeaves can obtain information about the logged on user both locally and for Remote Desktop sessions.

### S1240 - RedLine Stealer

RedLine Stealer has obtained the username from the victim’s machine.

### S0125 - Remsec

Remsec can obtain information about the current user.

### S0379 - Revenge RAT

Revenge RAT gathers the username from the system.

### S0433 - Rifdoor

Rifdoor has the ability to identify the username on the compromised host.

### S0448 - Rising Sun

Rising Sun can detect the username of the infected host.

### S0270 - RogueRobin

RogueRobin collects the victim’s username and whether that user is an admin.

### S0085 - S-Type

S-Type has run tests to determine the privilege level of the compromised user.

### S0461 - SDBbot

SDBbot has the ability to identify the user on a compromised host.

### S0450 - SHARPSTATS

SHARPSTATS has the ability to identify the username on the compromised host.

### S0692 - SILENTTRINITY

SILENTTRINITY can gather a list of logged on users.

### S0533 - SLOTHFULMEDIA

SLOTHFULMEDIA has collected the username from a victim machine.

### S0649 - SMOKEDHAM

SMOKEDHAM has used <code>whoami</code> commands to identify system owners.

### S1037 - STARWHALE

STARWHALE can gather the username from an infected host.

### S0559 - SUNBURST

SUNBURST collected the username from a compromised host.

### S1064 - SVCReady

SVCReady can collect the username from an infected host.

### S1018 - Saint Bot

Saint Bot can collect the username from a compromised host.

### S0382 - ServHelper

ServHelper will attempt to enumerate the username of the victim.

### S0596 - ShadowPad

ShadowPad has collected the username of the victim system.

### S0610 - SideTwist

SideTwist can collect the username on a targeted system.

### S1035 - Small Sieve

Small Sieve can obtain the id of a logged in user.

### S1124 - SocGholish

SocGholish can use `whoami` to obtain the username from a compromised host.

### S0627 - SodaMaster

SodaMaster can identify the username on a compromised host.

### S0615 - SombRAT

SombRAT can execute <code>getinfo</code>  to identify the username on a compromised host.

### S0543 - Spark

Spark has run the whoami command and has a built-in command to identify the user logged in.

### S0374 - SpeakUp

SpeakUp uses the <code>whoami</code> command.

### S1030 - Squirrelwaffle

Squirrelwaffle can collect the user name from a compromised host.

### S0058 - SslMM

SslMM sends the logged-on username to its hard-coded C2.

### S1034 - StrifeWater

StrifeWater can collect the user name from the victim's machine.

### S0242 - SynAck

SynAck gathers user names from infected hosts.

### S0060 - Sys10

Sys10 collects the account name of the logged-in user and sends it to the C2.

### S0663 - SysUpdate

SysUpdate can collect the username from a compromised host.

### S0098 - T9000

T9000 gathers and beacons the username of the logged in account during installation. It will also gather the username of running processes to determine if it is running as SYSTEM.

### S1239 - TONESHELL

TONESHELL has obtained the username from an infected host.

### S0266 - TrickBot

TrickBot can identify the user and groups the user belongs to on a compromised host.

### S0094 - Trojan.Karagany

Trojan.Karagany can gather information about the user on a compromised host.

### S0647 - Turian

Turian can retrieve usernames.

### S0275 - UPPERCUT

UPPERCUT has the capability to collect the current logged on user’s username from a machine.

### S0130 - Unknown Logger

Unknown Logger can obtain information about the victim usernames.

### S0257 - VERMIN

VERMIN gathers the username from the victim’s machine.

### S0476 - Valak

Valak can gather information regarding the user.

### S0155 - WINDSHIELD

WINDSHIELD can gather the victim user name.

### S0219 - WINERACK

WINERACK can gather information on the victim username.

### S0515 - WellMail

WellMail can identify the current username on the victim system.

### S0514 - WellMess

WellMess can collect the username on the victim machine to send to C2.

### S0059 - WinMM

WinMM uses NetUser-GetInfo to identify that it is running under an “Admin” account on the local system.

### S1065 - Woody RAT

Woody RAT can retrieve a list of user accounts and usernames from an infected machine.

### S0161 - XAgentOSX

XAgentOSX contains the getInfoOSX function to return the OS X version as well as the current user.

### S1207 - XLoader

XLoader can identify the username from a victim machine.

### S1248 - XORIndex Loader

XORIndex Loader has collected the username from the victim host.

### S0251 - Zebrocy

Zebrocy gets the username from the system.

### S0412 - ZxShell

ZxShell can collect the owner and organization information from the target workstation.

### S1013 - ZxxZ

ZxxZ can collect the username from a compromised host.

### S1059 - metaMain

metaMain can collect the username from a compromised host.

### S0385 - njRAT

njRAT enumerates the current user during the initial infection.

### S0248 - yty

yty collects the victim’s username.

### S0350 - zwShell

zwShell can obtain the name of the logged-in user on the victim.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0017 - C0017

During C0017, APT41 used `whoami` to gather information from victim machines.

### C0018 - C0018

During C0018, the threat actors collected `whoami` information via PowerShell scripts.

### C0001 - Frankenstein

During Frankenstein, the threat actors used Empire to enumerate hosts and gather username, machine name, and administrative permissions information.

### C0002 - Night Dragon

During Night Dragon, threat actors used password cracking and pass-the-hash tools to discover usernames and passwords.

### C0012 - Operation CuckooBees

During Operation CuckooBees, the threat actors used the `query user` and `whoami` commands as part of their advanced reconnaissance.

### C0014 - Operation Wocao

During Operation Wocao, threat actors enumerated sessions and users on a remote host, and identified privileged users logged into a targeted system.

### C0058 - SharePoint ToolShell Exploitation

During SharePoint ToolShell Exploitation, threat actors executed `whoami` on victim machines to enumerate user context and validate privilege levels.
