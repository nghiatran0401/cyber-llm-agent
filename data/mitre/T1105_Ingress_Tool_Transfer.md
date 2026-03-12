# T1105 - Ingress Tool Transfer

**Tactic:** Command and Control
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1105

## Description

Adversaries may transfer tools or other files from an external system into a compromised environment. Tools or files may be copied from an external adversary-controlled system to the victim network through the command and control channel or through alternate protocols such as ftp. Once present, adversaries may also transfer/spread tools between victim devices within a compromised environment (i.e. Lateral Tool Transfer). 

On Windows, adversaries may use various utilities to download tools, such as `copy`, `finger`, certutil, and PowerShell commands such as <code>IEX(New-Object Net.WebClient).downloadString()</code> and <code>Invoke-WebRequest</code>. On Linux and macOS systems, a variety of utilities also exist, such as `curl`, `scp`, `sftp`, `tftp`, `rsync`, `finger`, and `wget`.  A number of these tools, such as `wget`, `curl`, and `scp`, also exist on ESXi. After downloading a file, a threat actor may attempt to verify its integrity by checking its hash value (e.g., via `certutil -hashfile`).

Adversaries may also abuse installers and package managers, such as `yum` or `winget`, to download tools to victim hosts. Adversaries have also abused file application features, such as the Windows `search-ms` protocol handler, to deliver malicious files to victims through remote file searches invoked by User Execution (typically after interacting with Phishing lures).

Files can also be transferred using various Web Services as well as native or otherwise present tools on the victim system. In some cases, adversaries may be able to leverage services that sync between a web-based and an on-premises client, such as Dropbox or OneDrive, to transfer files onto victim systems. For example, by compromising a cloud account and logging into the service's web portal, an adversary may be able to trigger an automatic syncing process that transfers the file onto the victim's machine.

## Detection

### Detection Analytics

**Analytic 0165**

Unusual or uncommon processes initiate network connections to external destinations followed by file creation (tools downloaded).

**Analytic 0166**

Shell-based tools (curl, wget, scp) initiate connections to external domains followed by creation of executable files on disk.

**Analytic 0167**

Process execution of curl or wget followed by a network connection and a file created in temporary or user-specific directories.

**Analytic 0168**

Command line interface or vCLI triggers remote transfer using wget or curl, writing files into datastore paths or local tmp directories.

**Analytic 0169**

Network device logs show anomalous inbound file transfers or uncharacteristic flows with high payload volume to network devices with storage or automation hooks.


## Mitigations

### M1037 - Filter Network Traffic

Use network filtering to block outbound traffic from compromised systems to unapproved external destinations. Restricting access to known, trusted IP addresses and protocols can prevent attackers from downloading malicious tools or payloads onto compromised servers after gaining initial access.

### M1031 - Network Intrusion Prevention

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware or unusual data transfer over known protocols like FTP can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0469 - ABK

ABK has the ability to download files from C2.

### S1074 - ANDROMEDA

ANDROMEDA can download additional payloads from C2.

### S1028 - Action RAT

Action RAT has the ability to download additional payloads onto an infected machine.

### S0331 - Agent Tesla

Agent Tesla can download additional files for execution on the victim’s machine.

### S0092 - Agent.btz

Agent.btz attempts to download an encrypted binary from a specified domain.

### S1025 - Amadey

Amadey can download and execute files to further infect a host machine with additional malware.

### S0504 - Anchor

Anchor can download additional payloads.

### S0456 - Aria-body

Aria-body has the ability to download additional payloads from C2.

### S0373 - Astaroth

Astaroth uses certutil and BITSAdmin to download additional malware.

### S1087 - AsyncRAT

AsyncRAT has the ability to download files over SFTP.

### S0438 - Attor

Attor can download additional plugins, updates and other files.

### S0347 - AuditCred

AuditCred can download files and additional malware.

### S0473 - Avenger

Avenger has the ability to download files from C2 to a compromised host.

### S0344 - Azorult

Azorult can download and execute additional files. Azorult has also downloaded a ransomware payload called Hermes.

### S0642 - BADFLICK

BADFLICK has download files from its C2 server.

### S1081 - BADHATCH

BADHATCH has the ability to load a second stage malicious DLL file onto a compromised machine.

### S0128 - BADNEWS

BADNEWS is capable of downloading additional files through C2 channels, including a new version of itself.

### S0470 - BBK

BBK has the ability to download files from C2 to the infected host.

### S0017 - BISCUIT

BISCUIT has a command to download a file from the C2 server.

### S0190 - BITSAdmin

BITSAdmin can be used to create BITS Jobs to upload and/or download files.

### S0520 - BLINDINGCAN

BLINDINGCAN has downloaded files to a victim machine.

### S0657 - BLUELIGHT

BLUELIGHT can download additional files onto the host.

### S0360 - BONDUPDATER

BONDUPDATER can download or upload files from its C2 server.

### S1118 - BUSHWALK

BUSHWALK can write malicious payloads sent through a web request’s command parameter.

### S0414 - BabyShark

BabyShark has downloaded additional files from the C2.

### S0475 - BackConfig

BackConfig can download and execute additional payloads on a compromised host.

### S0093 - Backdoor.Oldrea

Backdoor.Oldrea can download additional modules from C2.

### S0337 - BadPatch

BadPatch can download and execute or update malware.

### S0234 - Bandook

Bandook can download files to the system.

### S0239 - Bankshot

Bankshot uploads files and secondary payloads to the victim's machine.

### S0534 - Bazar

Bazar can download and deploy additional payloads, including ransomware and post-exploitation frameworks such as Cobalt Strike.

### S1246 - BeaverTail

BeaverTail has been used to download a malicious payload to include Python based malware InvisibleFerret.

### S0574 - BendyBear

BendyBear is designed to download an implant from a C2 server.

### S0268 - Bisonal

Bisonal has the capability to download files to execute on the victim’s machine.

### S0564 - BlackMould

BlackMould has the ability to download files to the victim's machine.

### S0486 - Bonadan

Bonadan can download additional modules from the C2 server.

### S0635 - BoomBox

BoomBox has the ability to download next stage malware components to a compromised system.

### S0651 - BoxCaon

BoxCaon can download files.

### S0204 - Briba

Briba downloads files onto infected hosts.

### S1063 - Brute Ratel C4

Brute Ratel C4 can download files to compromised hosts.

### S1039 - Bumblebee

Bumblebee can download and execute additional payloads including through the use of a `Dex` command.

### S0482 - Bundlore

Bundlore can download and execute new versions of itself.

### S0465 - CARROTBALL

CARROTBALL has the ability to download and install a remote payload.

### S0462 - CARROTBAT

CARROTBAT has the ability to download and execute a remote file via certutil.

### S1224 - CASTLETAP

CASTLETAP can transfer files to compromised network devices.

### S1149 - CHIMNEYSWEEP

CHIMNEYSWEEP can download additional files from C2.

### S0023 - CHOPSTICK

CHOPSTICK is capable of performing remote file transmission.

### S0137 - CORESHELL

CORESHELL downloads another dropper from its C2 server.

### S0527 - CSPY Downloader

CSPY Downloader can download additional tools to a compromised host.

### S0274 - Calisto

Calisto has the capability to upload and download files to the victim's machine.

### S0077 - CallMe

CallMe has the capability to download a file to the victim from the C2 server.

### S0351 - Cannon

Cannon can download a payload for execution.

### S0484 - Carberp

Carberp can download and execute new plugins from the C2 server.

### S0348 - Cardinal RAT

Cardinal RAT can download and execute additional payloads.

### S0572 - Caterpillar WebShell

Caterpillar WebShell has a module to download and upload files to the system.

### S0144 - ChChes

ChChes is capable of downloading files, including additional modules.

### S0631 - Chaes

Chaes can download additional files onto an infected machine.

### S0674 - CharmPower

CharmPower has the ability to download additional modules to a compromised host.

### S0020 - China Chopper

China Chopper's server component can download remote files.

### S0667 - Chrommme

Chrommme can download its code from C2.

### S0054 - CloudDuke

CloudDuke downloads and executes additional malware from either a Web address or a Microsoft OneDrive account.

### S0154 - Cobalt Strike

Cobalt Strike can deliver additional payloads to victim machines.

### S0369 - CoinTicker

CoinTicker executes a Python script to download its second stage.

### S0608 - Conficker

Conficker downloads an HTTP server to the infected machine.

### S0492 - CookieMiner

CookieMiner can download additional scripts from a web server.

### S0614 - CostaBricks

CostaBricks has been used to load SombRAT onto a compromised host.

### S1023 - CreepyDrive

CreepyDrive can download files to the compromised host.

### S0115 - Crimson

Crimson contains a command to retrieve files from its C2 server.

### S0498 - Cryptoistic

Cryptoistic has the ability to send and receive files.

### S0625 - Cuba

Cuba can download files from its C2 server.

### S0687 - Cyclops Blink

Cyclops Blink has the ability to download files to target systems.

### S0255 - DDKONG

DDKONG downloads and uploads files on the victim’s machine.

### S0616 - DEATHRANSOM

DEATHRANSOM can download files to a compromised host.

### S0213 - DOGCALL

DOGCALL can download and execute additional payloads.

### S0694 - DRATzarus

DRATzarus can deploy additional tools onto an infected machine.

### S1159 - DUSTTRAP

DUSTTRAP can retrieve and load additional payloads.

### S0497 - Dacls

Dacls can download its payload from a C2 server.

### S1014 - DanBot

DanBot can download additional files to a targeted system.

### S0334 - DarkComet

DarkComet can load any files onto the infected machine to execute.

### S1111 - DarkGate

DarkGate retrieves cryptocurrency mining payloads and commands in encrypted traffic from its command and control server. DarkGate uses Windows Batch scripts executing the <code>curl</code> command to retrieve follow-on payloads. DarkGate has stolen `sitemanager.xml` and `recentservers.xml` from `%APPDATA%\FileZilla\` if present.

### S1066 - DarkTortilla

DarkTortilla can download additional packages for keylogging, cryptocurrency mining, and other capabilities; it can also retrieve malicious payloads such as Agent Tesla, AsyncRat, NanoCore, RedLine, Cobalt Strike, and Metasploit.

### S0187 - Daserf

Daserf can download remote files.

### S0354 - Denis

Denis deploys additional backdoors and hacking tools to the system.

### S0659 - Diavol

Diavol can receive configuration updates and additional payloads including wscpy.exe from C2.

### S0200 - Dipsind

Dipsind can download remote files.

### S1088 - Disco

Disco can download files to targeted systems via SMB.

### S1021 - DnsSystem

DnsSystem can download files to compromised systems after receiving a command with the string `downloaddd`.

### S0600 - Doki

Doki has downloaded scripts from C2.

### S0695 - Donut

Donut can download and execute previously staged shellcode payloads.

### S0134 - Downdelph

After downloading its main config file, Downdelph downloads multiple payloads from C2 servers.

### S0547 - DropBook

DropBook can download and execute additional files.

### S0502 - Drovorub

Drovorub can download files to a compromised host.

### S0567 - Dtrack

Dtrack’s can download and upload a file to the victim’s computer.

### S0024 - Dyre

Dyre has a command to download and executes additional files.

### S0568 - EVILNUM

EVILNUM can download and upload files to the victim's computer.

### S0624 - Ecipekac

Ecipekac can download additional payloads to a compromised host.

### S0554 - Egregor

Egregor has the ability to download files from its C2 server.

### S0081 - Elise

Elise can download additional files from the C2 server for execution.

### S0082 - Emissary

Emissary has the capability to download files from the C2 server.

### S0367 - Emotet

Emotet can download follow-on payloads and items via malicious `url` parameters in obfuscated PowerShell code.

### S0363 - Empire

Empire can upload and download to and from a victim machine.

### S0396 - EvilBunny

EvilBunny has downloaded additional Lua scripts from the C2.

### S0401 - Exaramel for Linux

Exaramel for Linux has a command to download a file from  and to a remote C2 server.

### S0569 - Explosive

Explosive has a function to download a file to the infected system.

### S0267 - FELIXROOT

FELIXROOT downloads and uploads files to and from the victim’s machine.

### S0628 - FYAnti

FYAnti can download additional payloads to a compromised host.

### S0171 - Felismus

Felismus can download files from remote servers.

### S0696 - Flagpro

Flagpro can download additional malware from the C2 server.

### S0381 - FlawedAmmyy

FlawedAmmyy can transfer files from C2.

### S0661 - FoggyWeb

FoggyWeb can receive additional malicious components from an actor controlled C2 server and execute them on a compromised AD FS server.

### S1044 - FunnyDream

FunnyDream can download additional files onto a compromised host.

### S0168 - Gazer

Gazer can execute a task to download a file.

### S0666 - Gelsemium

Gelsemium can download additional plug-ins to a compromised host.

### S0249 - Gold Dragon

Gold Dragon can download additional components from the C2 server.

### S0588 - GoldMax

GoldMax can download and execute additional files.

### S0493 - GoldenSpy

GoldenSpy constantly attempts to download and execute files from the remote C2, including GoldenSpy itself if not found on the system.

### S1138 - Gootloader

Gootloader can fetch second stage code from hardcoded web domains.

### S0531 - Grandoreiro

Grandoreiro can download its second stage from a hardcoded URL within the loader's code.

### S0342 - GreyEnergy

GreyEnergy can download additional modules and payloads.

### S0632 - GrimAgent

GrimAgent has the ability to download and execute additional payloads.

### S0561 - GuLoader

GuLoader can download further malware for execution on the victim's machine.

### S0132 - H1N1

H1N1 contains a command to download and execute a file from a remotely hosted URL using WinINet HTTP requests.

### S0214 - HAPPYWORK

can download and execute a second-stage payload.

### S0376 - HOPLIGHT

HOPLIGHT has the ability to connect to a remote host in order to upload and download files.

### S0070 - HTTPBrowser

HTTPBrowser is capable of writing a file to the compromised system from the C2 server.

### S0499 - Hancitor

Hancitor has the ability to download additional files from C2.

### S1211 - Hannotog

Hannotog can download additional files to the victim machine.

### S1229 - Havoc

Havoc has the ability to upload files to infected systems.

### S0170 - Helminth

Helminth can download additional files.

### S1249 - HexEval Loader

HexEval Loader has been used to download a malicious payload to include BeaverTail.

### S0087 - Hi-Zor

Hi-Zor has the ability to upload and download files from its C2 server.

### S0394 - HiddenWasp

HiddenWasp downloads a tar compressed archive from a download server to the system.

### S0009 - Hikit

Hikit has the ability to download files to a compromised host.

### S0601 - Hildegard

Hildegard has downloaded additional scripts that build and run Monero cryptocurrency miners.

### S0431 - HotCroissant

HotCroissant has the ability to upload a file from the command and control (C2) server to the victim machine.

### S0203 - Hydraq

Hydraq creates a backdoor through which remote attackers can download files and additional malware components.

### S0398 - HyperBro

HyperBro has the ability to download additional files.

### S1152 - IMAPLoader

IMAPLoader is a loader used to retrieve follow-on payload encoded in email messages for execution on victim systems.

### S0483 - IcedID

IcedID has the ability to download additional modules and a configuration file from C2.

### S0604 - Industroyer

Industroyer downloads a shellcode payload from a remote C2 server and loads it into memory.

### S0260 - InvisiMole

InvisiMole can upload files to the victim's machine for operations.

### S1245 - InvisibleFerret

InvisibleFerret has downloaded “AnyDesk.exe” into the user’s home directory from the C2 server when checks for the service fail to identify its presence in the victim environment. InvisibleFerret has also been configured to download additional payloads using a command which calls to the /bow URI.

### S0015 - Ixeshe

Ixeshe can download and execute additional files.

### S0044 - JHUHUGIT

JHUHUGIT can retrieve an additional payload from its C2 server. JHUHUGIT has a command to download files to the victim’s machine.

### S0201 - JPIN

JPIN can download files and upgrade itself.

### S0648 - JSS Loader

JSS Loader has the ability to download malicious executables to a compromised host.

### S0528 - Javali

Javali can download payloads from remote C2 servers.

### S0215 - KARAE

KARAE can upload and download files, including second-stage malware.

### S0271 - KEYMARBLE

KEYMARBLE can upload files to the victim’s machine and can download additional payloads.

### S0526 - KGH_SPY

KGH_SPY has the ability to download and execute code from remote servers.

### S0669 - KOCTOPUS

KOCTOPUS has executed a PowerShell command to download a file to the system.

### S0356 - KONNI

KONNI can download files and execute them on the victim’s machine.

### S0088 - Kasidet

Kasidet has the ability to download and execute additional files.

### S0265 - Kazuar

Kazuar downloads additional plug-ins to load on the victim’s machine, including the ability to upgrade and replace its own binary.

### S0585 - Kerrdown

Kerrdown can download specific payloads to a compromised host based on OS architecture.

### S0487 - Kessel

Kessel can download additional modules from the C2 server.

### S1020 - Kevin

Kevin can download files to the compromised host.

### S0387 - KeyBoy

KeyBoy has a download and upload functionality.

### S0599 - Kinsing

Kinsing has downloaded additional lateral movement scripts from C2.

### S0437 - Kivars

Kivars has the ability to download and execute files.

### S0250 - Koadic

Koadic can download additional files and tools.

### S0236 - Kwampirs

Kwampirs downloads additional files from C2 servers.

### S0042 - LOWBALL

LOWBALL uses the Dropbox API to request two files, one of which is the same file as the one dropped by the malicious email attachment. This is most likely meant to be a mechanism to update the compromised host with a new version of the LOWBALL malware.

### S1160 - Latrodectus

Latrodectus can download and execute PEs, DLLs, and shellcode from C2.

### S0395 - LightNeuron

LightNeuron has the ability to download and execute additional files.

### S1185 - LightSpy

On macOS, LightSpy downloads a `.json` file from the C2 server. The `.json` file contains metadata about the plugins to be downloaded, including their URL, name, version, and MD5 hash. LightSpy retrieves the plugins specified in the `.json` file, which are compiled `.dylib` files. These `.dylib` files provide task and platform specific functionality. LightSpy also imports open-source libraries to manage socket connections.

### S0211 - Linfo

Linfo creates a backdoor through which remote attackers can download files onto compromised hosts.

### S0513 - LiteDuke

LiteDuke has the ability to download files.

### S0680 - LitePower

LitePower has the ability to download payloads containing system commands to a compromised host.

### S0681 - Lizar

Lizar can download additional plugins, files, and tools.

### S0447 - Lokibot

Lokibot downloaded several staged items onto the victim's machine.

### S0451 - LoudMiner

LoudMiner used SCP to update the miner from the C2.

### S0532 - Lucifer

Lucifer can download and execute a replica of itself using certutil.

### S0500 - MCMD

MCMD can upload additional files to a compromised host.

### S1016 - MacMa

MacMa has downloaded additional files, including an exploit for used privilege escalation.

### S0409 - Machete

Machete can download additional files for execution on the victim’s machine.

### S1060 - Mafalda

Mafalda can download additional files onto the compromised host.

### S1182 - MagicRAT

MagicRAT can import and execute additional payloads.

### S0652 - MarkiRAT

MarkiRAT can download additional files and tools from its C2 server, including through the use of BITSAdmin.

### S0459 - MechaFlounder

MechaFlounder has the ability to upload and download files to and from a compromised host.

### S0530 - Melcoz

Melcoz has the ability to download additional files to a compromised host.

### S0455 - Metamorfo

Metamorfo has used MSI files to download additional files to execute.

### S0688 - Meteor

Meteor has the ability to download additional files for execution on the victim's machine.

### S0339 - Micropsia

Micropsia can download and execute an executable from the C2 server.

### S1015 - Milan

Milan has received files from C2 and stored them in log folders beginning with the character sequence `a9850d2f`.

### S0051 - MiniDuke

MiniDuke can download additional encrypted backdoors onto the victim via GIF files.

### S0084 - Mis-Type

Mis-Type has downloaded additional malware and files onto a compromised host.

### S0083 - Misdat

Misdat is capable of downloading files from the C2.

### S0080 - Mivast

Mivast has the capability to download and execute .exe files.

### S0079 - MobileOrder

MobileOrder has a command to download a file from the C2 server to the victim mobile device's SD card.

### S0553 - MoleNet

MoleNet can download additional payloads from the C2.

### S1026 - Mongall

Mongall can download files to targeted systems.

### S0284 - More_eggs

More_eggs can download and launch additional payloads.

### S0256 - Mosquito

Mosquito can upload and download files to the victim.

### S0272 - NDiskMonitor

NDiskMonitor can download and execute a file from given URL.

### S0198 - NETWIRE

NETWIRE can downloaded payloads from C2 to the compromised host.

### S1192 - NICECURL

NICECURL has the ability to download additional content onto an infected machine, e.g. by using `curl`.

### S0353 - NOKKI

NOKKI has downloaded a remote module for execution.

### S0228 - NanHaiShu

NanHaiShu can download additional files from URLs.

### S0336 - NanoCore

NanoCore has the capability to download and activate additional modules for execution.

### S0247 - NavRAT

NavRAT can download files remotely.

### S0630 - Nebulae

Nebulae can download files from C2.

### S1189 - Neo-reGeorg

Neo-reGeorg has the ability to download files to targeted systems.

### S0691 - Neoichor

Neoichor can download additional files onto a compromised host.

### S0210 - Nerex

Nerex creates a backdoor through which remote attackers can download files onto a compromised host.

### S0457 - Netwalker

Operators deploying Netwalker have used psexec and certutil to retrieve the Netwalker payload.

### S0118 - Nidiran

Nidiran can download and execute files.

### S1090 - NightClub

NightClub can load multiple additional plugins on an infected host.

### S1170 - ODAgent

ODAgent has the ability to download and execute files on compromised systems.

### S0402 - OSX/Shlayer

OSX/Shlayer can download payloads, and extract bytes from files. OSX/Shlayer uses the <code>curl -fsL "$url" >$tmp_path</code> command to download malicious payloads into a temporary directory.

### S0352 - OSX_OCEANLOTUS.D

OSX_OCEANLOTUS.D has a command to download and execute a file on the victim’s machine.

### S0340 - Octopus

Octopus can download additional files and tools onto the victim’s machine.

### S1172 - OilBooster

OilBooster can download and execute files from an actor-controlled OneDrive account.

### S1171 - OilCheck

OilCheck can download staged payloads from an actor-controlled infrastructure.

### S0439 - Okrum

Okrum has built-in commands for uploading, downloading, and executing files to the system.

### S0264 - OopsIE

OopsIE can download files from its C2 server to the victim's machine.

### S0229 - Orz

Orz can download files onto the victim.

### S1017 - OutSteel

OutSteel can download files from its C2 server.

### S0598 - P.A.S. Webshell

P.A.S. Webshell can upload and download files to and from compromised hosts.

### S0626 - P8RAT

P8RAT can download additional payloads to a target system.

### S0254 - PLAINTEE

PLAINTEE has downloaded and executed additional plugins.

### S0435 - PLEAD

PLEAD has the ability to upload and download files to and from an infected host.

### S0150 - POSHSPY

POSHSPY downloads and executes additional PowerShell code and Windows binaries.

### S0145 - POWERSOURCE

POWERSOURCE has been observed being used to download TEXTMATE and the Cobalt Strike Beacon payload onto victims.

### S0223 - POWERSTATS

POWERSTATS can retrieve and execute additional PowerShell payloads from the C2 server.

### S0184 - POWRUNER

POWRUNER can download or upload files from its C2 server.

### S0613 - PS1

CostaBricks can download additional payloads onto a compromised host.

### S1228 - PUBLOAD

PUBLOAD has acted as a stager that can download the next-stage payload from its C2 server. PUBLOAD has also delivered FDMTP as a secondary control tool and PTSOCKET for exfiltration to some infected systems.

### S0196 - PUNCHBUGGY

PUNCHBUGGY can download additional files and payloads to compromised hosts.

### S0664 - Pandora

Pandora can load additional drivers and files onto a victim machine.

### S0208 - Pasam

Pasam creates a backdoor through which remote attackers can upload files.

### S0587 - Penquin

Penquin can execute the command code <code>do_download</code> to retrieve remote files from C2.

### S0643 - Peppy

Peppy can download and execute remote files.

### S0501 - PipeMon

PipeMon can install additional modules via C2 commands.

### S0124 - Pisloader

Pisloader has a command to upload a file to the victim machine.

### S0013 - PlugX

PlugX has a module to download and execute files on the compromised machine.

### S0428 - PoetRAT

PoetRAT has the ability to copy files and download/upload files into C2 channels using FTP and HTTPS.

### S0012 - PoisonIvy

PoisonIvy creates a backdoor through which remote attackers can upload files.

### S0518 - PolyglotDuke

PolyglotDuke can retrieve payloads from the C2 server.

### S0453 - Pony

Pony can download additional files onto the infected system.

### S0139 - PowerDuke

PowerDuke has a command to download a file.

### S1173 - PowerExchange

PowerExchange can decode Base64-encoded files and call `WriteAllBytes` to write the files to compromised hosts.

### S1012 - PowerLess

PowerLess can download additional payloads to a compromised host.

### S0685 - PowerPunch

PowerPunch can download payloads from adversary infrastructure.

### S0078 - Psylo

Psylo has a command to download a file to the system from its C2 server.

### S0147 - Pteranodon

Pteranodon can download and execute additional files.

### S0192 - Pupy

Pupy can upload and download to/from a victim machine.

### S0650 - QakBot

QakBot has the ability to download additional components and malware.

### S0262 - QuasarRAT

QuasarRAT can download files to the victim’s machine and execute them.

### S0686 - QuietSieve

QuietSieve can download and execute payloads on a target host.

### S0055 - RARSTONE

RARSTONE downloads its backdoor component from a C2 server and loads it directly into memory.

### S0241 - RATANKBA

RATANKBA uploads and downloads information.

### S0662 - RCSession

RCSession has the ability to drop additional files to an infected machine.

### S0495 - RDAT

RDAT can download files via DNS.

### S0496 - REvil

REvil can download a copy of itself from an attacker controlled IP address to the victim machine.

### S0258 - RGDoor

RGDoor uploads and downloads files to and from the victim’s machine.

### S1222 - RIFLESPINE

RIFLESPINE can download and execute files.

### S0240 - ROKRAT

ROKRAT can retrieve additional malicious payloads from its C2 server.

### S0148 - RTM

RTM can download additional files.

### S1148 - Raccoon Stealer

Raccoon Stealer downloads various library files enabling interaction with various data stores and structures to facilitate follow-on information theft.

### S0629 - RainyDay

RainyDay can download files to a compromised host.

### S1130 - Raspberry Robin

Raspberry Robin retrieves its second stage payload in a variety of ways such as through msiexec.exe abuse, or running the curl command to download the payload to the victim's <code>%AppData%</code> folder.

### S0153 - RedLeaves

RedLeaves is capable of downloading a file from a specified URL.

### S1240 - RedLine Stealer

RedLine Stealer has the ability download additional payloads.

### S0511 - RegDuke

RegDuke can download files from C2.

### S0332 - Remcos

Remcos can upload and download files to and from the victim’s machine.

### S0166 - RemoteCMD

RemoteCMD copies a file over to the remote system before execution.

### S0592 - RemoteUtilities

RemoteUtilities can upload and download files to and from a target machine.

### S0125 - Remsec

Remsec contains a network loader to receive executable modules from remote attackers and run them on the local victim. It can also upload and download files over HTTP and HTTPS.

### S0379 - Revenge RAT

Revenge RAT has the ability to upload and download files.

### S0270 - RogueRobin

RogueRobin can save a new file to the system from the C2 server.

### S0085 - S-Type

S-Type can download additional files onto a compromised host.

### S0461 - SDBbot

SDBbot has the ability to download a DLL from C2 to a compromised host.

### S0185 - SEASHARPEE

SEASHARPEE can download remote files onto victims.

### S0450 - SHARPSTATS

SHARPSTATS has the ability to upload and download files.

### S0217 - SHUTTERSPEED

SHUTTERSPEED can download and execute an arbitary executable.

### S0692 - SILENTTRINITY

SILENTTRINITY can load additional files and tools, including Mimikatz.

### S1110 - SLIGHTPULSE

RAPIDPULSE can transfer files to and from compromised hosts.

### S0533 - SLOTHFULMEDIA

SLOTHFULMEDIA has downloaded files onto a victim machine.

### S0218 - SLOWDRIFT

SLOWDRIFT downloads additional payloads.

### S0649 - SMOKEDHAM

SMOKEDHAM has used Powershell to download UltraVNC and ngrok from third-party file sharing sites.

### S0390 - SQLRat

SQLRat can make a direct SQL connection to a Microsoft database controlled by the attackers, retrieve an item from the bindata table, then write and execute the file on disk.

### S1112 - STEADYPULSE

STEADYPULSE can add lines to a Perl script on a targeted server to import additional Perl modules.

### S0559 - SUNBURST

SUNBURST delivered different payloads, including TEARDROP in at least one instance.

### S1064 - SVCReady

SVCReady has the ability to download additional tools such as the RedLine Stealer to an infected host.

### S1018 - Saint Bot

Saint Bot can download additional files onto a compromised host.

### S0074 - Sakula

Sakula has the capability to download files.

### S1168 - SampleCheck5000

SampleCheck5000 can download additional payloads to compromised hosts.

### S1099 - Samurai

Samurai has been used to deploy other malware including Ninja.

### S1085 - Sardonic

Sardonic has the ability to upload additional malicious files to a compromised machine.

### S0053 - SeaDuke

SeaDuke is capable of uploading and downloading files.

### S0345 - Seasalt

Seasalt has a command to download additional files.

### S0382 - ServHelper

ServHelper may download additional files to execute.

### S0639 - Seth-Locker

Seth-Locker has the ability to download and execute files on a compromised host.

### S0596 - ShadowPad

ShadowPad has downloaded code from a C2 server.

### S0140 - Shamoon

Shamoon can download an executable to run on the victim.

### S1019 - Shark

Shark  can download additional files from its C2 via HTTP or DNS.

### S1089 - SharpDisco

SharpDisco has been used to download a Python interpreter to `C:\Users\Public\WinTN\WinTN.exe` as well as other plugins from external sources.

### S0546 - SharpStage

SharpStage has the ability to download and execute additional payloads via a DropBox API.

### S0444 - ShimRat

ShimRat can download additional files.

### S0445 - ShimRatReporter

ShimRatReporter had the ability to download additional payloads.

### S0589 - Sibot

Sibot can download and execute a payload onto a compromised system.

### S0610 - SideTwist

SideTwist has the ability to download additional files.

### S0468 - Skidmap

Skidmap has the ability to download files on an infected host.

### S0633 - Sliver

Sliver can download additional content and files from the Sliver server to the client residing on the victim machine using the <code>upload</code> command.

### S1035 - Small Sieve

Small Sieve has the ability to download files.

### S0226 - Smoke Loader

Smoke Loader downloads a new version of itself once it has installed. It also downloads additional plugins.

### S1086 - Snip3

Snip3 can download additional payloads to compromised systems.

### S1124 - SocGholish

SocGholish can download additional malware to infected hosts.

### S0627 - SodaMaster

SodaMaster has the ability to download additional payloads from C2 to the targeted system.

### S1166 - Solar

Solar has the ability to download and execute files.

### S0615 - SombRAT

SombRAT has the ability to download and execute additional payloads.

### S0516 - SoreFang

SoreFang can download additional payloads from C2.

### S0374 - SpeakUp

SpeakUp downloads and executes additional files from a remote server.

### S1140 - Spica

Spica can upload and download files to and from compromised hosts.

### S0646 - SpicyOmelette

SpicyOmelette can download malicious files from threat actor controlled AWS URL's.

### S1030 - Squirrelwaffle

Squirrelwaffle has downloaded and executed additional encoded payloads.

### S0380 - StoneDrill

StoneDrill has downloaded and dropped temporary files containing scripts; it additionally has a function to upload files from the victims machine.

### S1183 - StrelaStealer

StrelaStealer installers have used obfuscated PowerShell scripts to retrieve follow-on payloads from WebDAV servers.

### S1034 - StrifeWater

StrifeWater can download updates and auxiliary modules.

### S0491 - StrongPity

StrongPity can download files to specified targets.

### S0663 - SysUpdate

SysUpdate has the ability to download files to a compromised host.

### S0586 - TAINTEDSCRIBE

TAINTEDSCRIBE can download additional modules from its C2 server.

### S1193 - TAMECAT

TAMECAT has used `wget` and `curl` to download additional content.

### S0164 - TDTESS

TDTESS has a command to download and execute an additional file.

### S1239 - TONESHELL

TONESHELL has the ability to download additional files to the victim device.

### S0436 - TSCookie

TSCookie has the ability to upload and download files to and from the infected host.

### S0199 - TURNEDUP

TURNEDUP is capable of downloading additional files.

### S0263 - TYPEFRAME

TYPEFRAME can upload and download files to the victim’s machine.

### S0011 - Taidoor

Taidoor has downloaded additional files onto a compromised host.

### S0595 - ThiefQuest

ThiefQuest can download and execute payloads in-memory or from disk.

### S0665 - ThreatNeedle

ThreatNeedle can download additional tools to enable lateral movement.

### S0668 - TinyTurla

TinyTurla has the ability to act as a second-stage dropper used to infect the system with additional malware.

### S0671 - Tomiris

Tomiris can download files and execute them on a victim's system.

### S0266 - TrickBot

TrickBot downloads several additional files and saves them to the victim's machine.

### S0094 - Trojan.Karagany

Trojan.Karagany can upload, download, and execute files on the victim.

### S0647 - Turian

Turian can download additional files and tools from its C2.

### S0333 - UBoatRAT

UBoatRAT can upload and download files to the victim’s machine.

### S0275 - UPPERCUT

UPPERCUT can download and upload files to and from the victim’s machine.

### S0130 - Unknown Logger

Unknown Logger is capable of downloading remote files.

### S0022 - Uroburos

Uroburos can use a `Put` command to write files to an infected machine.

### S0386 - Ursnif

Ursnif has dropped payload and configuration files to disk. Ursnif has also been used to download and execute additional payloads.

### S0442 - VBShower

VBShower has the ability to download VBS files to the target computer.

### S0257 - VERMIN

VERMIN can download and upload files to the victim's machine.

### S1217 - VIRTUALPITA

VIRTUALPITA has the ability to upload and download files.

### S0476 - Valak

Valak has downloaded a variety of modules and payloads to the compromised host, including IcedID and NetSupport Manager RAT-based malware.

### S0636 - VaporRage

VaporRage has the ability to download malicious shellcode to compromised systems.

### S0207 - Vasport

Vasport can download files.

### S0180 - Volgmer

Volgmer can download remote files and additional payloads to the victim's machine.

### S0109 - WEBC2

WEBC2 can download and execute a file.

### S1115 - WIREFIRE

WIREFIRE has the ability to download files to compromised devices.

### S0670 - WarzoneRAT

WarzoneRAT can download and execute additional files.

### S0579 - Waterbear

Waterbear can receive and load executables from remote C2 servers.

### S0515 - WellMail

WellMail can receive data and executable scripts from C2.

### S0514 - WellMess

WellMess can write files to a compromised host.

### S0689 - WhisperGate

WhisperGate can download additional stages of malware from a Discord CDN channel.

### S0206 - Wiarp

Wiarp creates a backdoor through which remote attackers can download files.

### S0430 - Winnti for Linux

Winnti for Linux has the ability to deploy modules directly from command and control (C2) servers, possibly for remote command execution, file exfiltration, and socks5 proxying on the infected host.

### S0141 - Winnti for Windows

The Winnti for Windows dropper can place malicious payloads on targeted systems.

### S1065 - Woody RAT

Woody RAT can download files from its C2 server, including the .NET DLLs, `WoodySharpExecutor` and `WoodyPowerSession`.

### S0658 - XCSSET

XCSSET downloads browser specific AppleScript modules using a constructed URL with the <code>curl</code> command, <code>https://" & domain & "/agent/scripts/" & moduleName & ".applescript</code>.

### S1248 - XORIndex Loader

XORIndex Loader has been used to download a malicious payload to include BeaverTail.

### S0341 - Xbash

Xbash can download additional malicious files from its C2 server.

### S0388 - YAHOYAH

YAHOYAH uses HTTP GET requests to download other files that are executed in memory.

### S1114 - ZIPLINE

ZIPLINE can download files to be saved on the compromised system.

### S0086 - ZLib

ZLib has the ability to download files.

### S0251 - Zebrocy

Zebrocy obtains additional code to execute on the victim's machine, including the downloading of a secondary payload.

### S0230 - ZeroT

ZeroT can download additional payloads onto the victim.

### S0330 - Zeus Panda

Zeus Panda can download additional malware plug-in modules and execute them on the victim’s machine.

### S0672 - Zox

Zox can download files to a compromised machine.

### S0412 - ZxShell

ZxShell has a command to transfer files from a remote host.

### S1013 - ZxxZ

ZxxZ can download and execute additional files.

### S0471 - build_downer

build_downer has the ability to download files from C2 to the infected host.

### S0160 - certutil

certutil can be used to download files from a given URL.

### S0106 - cmd

cmd can be used to copy files to/from a remotely connected external system.

### S0472 - down_new

down_new has the ability to download files to the compromised host.

### S0404 - esentutl

esentutl can be used to copy files from a given URL.

### S0095 - ftp

ftp may be abused by adversaries to transfer tools or files from an external system into a compromised environment.

### S0032 - gh0st RAT

gh0st RAT can download files to the victim’s machine.

### S0283 - jRAT

jRAT can download and execute files.

### S1048 - macOS.OSAMiner

macOS.OSAMiner has used `curl` to download a Stripped Payloads from a public facing adversary-controlled webpage.

### S1059 - metaMain

metaMain can download files onto compromised systems.

### S0385 - njRAT

njRAT can download files to the victim’s machine.

### S1187 - reGeorg

reGeorg has the ability to download files to targeted systems.

### S0653 - xCaon

xCaon has a command to download files to the victim's machine.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0028 - 2015 Ukraine Electric Power Attack

During the 2015 Ukraine Electric Power Attack, Sandworm Team pushed additional malicious tools onto an infected system to steal user credentials, move laterally, and destroy data.

### C0040 - APT41 DUST

APT41 DUST involved execution of `certutil.exe` via web shell to download the DUSTPAN dropper.

### C0010 - C0010

During C0010, UNC3890 actors downloaded tools and malware onto a compromised host.

### C0015 - C0015

During C0015, the threat actors downloaded additional tools and files onto a compromised network.

### C0017 - C0017

During C0017, APT41 downloaded malicious payloads onto compromised systems.

### C0018 - C0018

During C0018, the threat actors downloaded additional tools, such as Mimikatz and Sliver, as well as Cobalt Strike and AvosLocker ransomware onto the victim network.

### C0021 - C0021

During C0021, the threat actors downloaded additional tools and files onto victim machines.

### C0026 - C0026

During C0026, the threat actors downloaded malicious payloads onto select compromised hosts.

### C0027 - C0027

During C0027, Scattered Spider downloaded tools using victim organization systems.

### C0004 - CostaRicto

During CostaRicto, the threat actors downloaded malware and tools onto a compromised host.

### C0029 - Cutting Edge

During Cutting Edge, threat actors leveraged exploits to download remote files to Ivanti Connect Secure VPNs.

### C0001 - Frankenstein

During Frankenstein, the threat actors downloaded files and tools onto a victim machine.

### C0007 - FunnyDream

During FunnyDream, the threat actors downloaded additional droppers and backdoors onto a compromised system.

### C0038 - HomeLand Justice

During HomeLand Justice, threat actors used web shells to download files to compromised infrastructure.

### C0035 - KV Botnet Activity

KV Botnet Activity included the use of scripts to download additional payloads when compromising network nodes.

### C0002 - Night Dragon

During Night Dragon, threat actors used administrative utilities to deliver Trojan components to remote systems.

### C0022 - Operation Dream Job

During Operation Dream Job, Lazarus Group downloaded multistage malware and tools onto a compromised host.

### C0006 - Operation Honeybee

During Operation Honeybee, the threat actors downloaded additional malware and malicious scripts onto a compromised host.

### C0048 - Operation MidnightEclipse

During Operation MidnightEclipse, threat actors downloaded additional payloads on compromised devices.

### C0013 - Operation Sharpshooter

During Operation Sharpshooter, additional payloads were downloaded after a target was infected with a first-stage downloader.

### C0014 - Operation Wocao

During Operation Wocao, threat actors downloaded additional files to the infected system.

### C0042 - Outer Space

During Outer Space, OilRig downloaded additional tools to comrpomised infrastructure.

### C0055 - Quad7 Activity

Quad7 Activity has downloaded additional binaries from a remote File Transfer Protocol (FTP) server to compromised devices.

### C0056 - RedPenguin

During RedPenguin, UNC3886 used backdoor malware capable of downloading files to compromised infrastructure.

### C0045 - ShadowRay

During ShadowRay, threat actors downloaded and executed the XMRig miner on targeted hosts.

### C0058 - SharePoint ToolShell Exploitation

During SharePoint ToolShell Exploitation, threat actors used a loader to download and execute ransomware.

### C0024 - SolarWinds Compromise

During the SolarWinds Compromise, APT29 downloaded additional malware, such as TEARDROP and Cobalt Strike, onto a compromised host following initial access.

### C0037 - Water Curupira Pikabot Distribution

Water Curupira Pikabot Distribution used Curl.exe to download the Pikabot payload from an external server, saving the file to the victim machine's temporary directory.
