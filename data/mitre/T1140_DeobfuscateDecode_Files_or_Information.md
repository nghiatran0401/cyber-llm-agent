# T1140 - Deobfuscate/Decode Files or Information

**Tactic:** Defense Evasion
**Platforms:** ESXi, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1140

## Description

Adversaries may use Obfuscated Files or Information to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it. Methods for doing that include built-in functionality of malware or by using utilities present on the system.

One such example is the use of certutil to decode a remote access tool portable executable file that has been hidden inside a certificate file. Another example is using the Windows <code>copy /b</code> or <code>type</code> command to reassemble binary fragments into a malicious payload.

Sometimes a user's action may be required to open it for deobfuscation or decryption as part of User Execution. The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary.

## Detection

### Detection Analytics

**Analytic 0767**

An adversary leverages built-in tools such as certutil.exe, powershell.exe, or copy.exe to decode, reassemble, or extract hidden malicious content from obfuscated containers or encoded formats. The decoding utility often spawns shortly after file staging or download and may be chained with script interpreters or further payload execution.

**Analytic 0768**

The adversary uses native utilities like base64, gzip, tar, or openssl to decode, decompress, or decrypt files that were previously staged or downloaded. These tools may be chained with curl/wget and executed via bash/zsh, often to extract an embedded payload or reverse shell script.

**Analytic 0769**

The adversary invokes built-in scripting or decoding tools like base64, plutil, or AppleScript-based utilities to decode files embedded in staging artifacts. Decoding often occurs post-download or as part of post-exploitation payload deployment via zsh, python, or osascript.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0469 - ABK

ABK has the ability to decrypt AES encrypted payloads.

### S1028 - Action RAT

Action RAT can use Base64 to decode actor-controlled C2 server communications.

### S0331 - Agent Tesla

Agent Tesla has the ability to decrypt strings encrypted with the Rijndael symmetric encryption algorithm.

### S1025 - Amadey

Amadey has decoded antivirus name strings.

### S1133 - Apostle

Apostle compiled code is obfuscated in an unspecified fashion prior to delivery to victims.

### S0584 - AppleJeus

AppleJeus has decoded files received from a C2.

### S0622 - AppleSeed

AppleSeed can decode its payload prior to execution.

### S0456 - Aria-body

Aria-body has the ability to decrypt the loader configuration and payload DLL.

### S0373 - Astaroth

Astaroth uses a fromCharCode() deobfuscation method to avoid explicitly writing execution commands and to hide its code.

### S0347 - AuditCred

AuditCred uses XOR and RC4 to perform decryption on the code functions.

### S0640 - Avaddon

Avaddon has decrypted encrypted strings.

### S0473 - Avenger

Avenger has the ability to decrypt files downloaded from C2.

### S1053 - AvosLocker

AvosLocker has deobfuscated XOR-encoded strings.

### S0344 - Azorult

Azorult uses an XOR key to decrypt content and uses Base64 to decode the C2 address.

### S0642 - BADFLICK

BADFLICK can decode shellcode using a custom rotating XOR cipher.

### S0470 - BBK

BBK has the ability to decrypt AES encrypted payloads.

### S0127 - BBSRAT

BBSRAT uses Expand to decompress a CAB file into executable content.

### S0520 - BLINDINGCAN

BLINDINGCAN has used AES and XOR to decrypt its DLLs.

### S1226 - BOOKWORM

BOOKWORM has decoded its Base64 encoded payload prior to execution.  BOOKWORM has also encrypted files with RC4 and has decrypted its payload prior to execution.

### S0415 - BOOSTWRITE

BOOSTWRITE has used a a 32-byte long multi-XOR key to decode data inside its payload.

### S1118 - BUSHWALK

BUSHWALK can Base64 decode and RC4 decrypt malicious payloads sent through a web request’s command parameter.

### S0638 - Babuk

Babuk has the ability to unpack itself into memory using XOR.

### S0414 - BabyShark

BabyShark has the ability to decode downloaded files prior to execution.

### S0475 - BackConfig

BackConfig has used a custom routine to decrypt strings.

### S0234 - Bandook

Bandook has decoded its PowerShell script.

### S0239 - Bankshot

Bankshot decodes embedded XOR strings.

### S0534 - Bazar

Bazar can decrypt downloaded payloads. Bazar also resolves strings and other artifacts at runtime.

### S0574 - BendyBear

BendyBear has decrypted function blocks using a XOR key during runtime to evade detection.

### S0268 - Bisonal

Bisonal has decoded strings in the malware using XOR and RC4.

### S1180 - BlackByte Ransomware

BlackByte Ransomware is distributed as an obfuscated JavaScript launcher file.

### S0635 - BoomBox

BoomBox can decrypt AES-encrypted files downloaded from C2.

### S1063 - Brute Ratel C4

Brute Ratel C4 has the ability to deobfuscate its payload prior to execution.

### S1039 - Bumblebee

Bumblebee can deobfuscate C2 server responses and unpack its code on targeted hosts.

### S0482 - Bundlore

Bundlore has used <code>openssl</code> to decrypt AES encrypted payload data. Bundlore has also used base64 and RC4 with a hardcoded key to deobfuscate data.

### S1224 - CASTLETAP

CASTLETAP can filter and deobfuscate an XOR encrypted activation string in the payload of an ICMP echo request.

### S1149 - CHIMNEYSWEEP

CHIMNEYSWEEP can use an embedded RC4 key to decrypt Windows API function strings.

### S1236 - CLAIMLOADER

CLAIMLOADER has decoded its payload prior to execution.

### S1105 - COATHANGER

COATHANGER decodes configuration items from a bundled file for command and control activity.

### S0335 - Carbon

Carbon decrypts task and configuration files for execution.

### S0348 - Cardinal RAT

Cardinal RAT decodes many of its artifacts and is decrypted (AES-128) after being downloaded.

### S0631 - Chaes

Chaes has decrypted an AES encrypted binary file to trigger the download of other files.

### S0674 - CharmPower

CharmPower can decrypt downloaded modules prior to execution.

### S1041 - Chinoxy

The Chinoxy dropping function can initiate decryption of its config file.

### S0667 - Chrommme

Chrommme can decrypt its encrypted internal code.

### S0660 - Clambling

Clambling can deobfuscate its payload prior to execution.

### S0611 - Clop

Clop has used a simple XOR operation to decrypt strings.

### S0154 - Cobalt Strike

Cobalt Strike can deobfuscate shellcode using a rolling XOR and decrypt metadata from Beacon sessions.

### S0369 - CoinTicker

CoinTicker decodes the initially-downloaded hidden encoded file using OpenSSL.

### S0126 - ComRAT

ComRAT has used unique per machine passwords to decrypt the orchestrator payload and a hardcoded XOR key to decrypt its communications module. ComRAT has also used a unique password to decrypt the file used for its hidden file system.

### S0575 - Conti

Conti has decrypted its payload using a hardcoded AES-256 key.

### S0492 - CookieMiner

CookieMiner has used Google Chrome's decryption and extraction operations.

### S1235 - CorKLOG

CorKLOG has decoded XOR encrypted strings.

### S0614 - CostaBricks

CostaBricks has the ability to use bytecode to decrypt embedded payloads.

### S0115 - Crimson

Crimson can decode its encoded PE file prior to execution.

### S1153 - Cuckoo Stealer

Cuckoo Stealer strings are deobfuscated prior to execution.

### S0687 - Cyclops Blink

Cyclops Blink can decrypt and parse instructions sent from C2.

### S0255 - DDKONG

DDKONG decodes an embedded configuration using XOR.

### S1052 - DEADEYE

DEADEYE has the ability to combine multiple sections of a binary which were broken up to evade detection into a single .dll prior to execution.

### S1134 - DEADWOOD

DEADWOOD XORs some strings within the binary using the value <code>0xD5</code>, and deobfuscates these items at runtime.

### S1158 - DUSTPAN

DUSTPAN decodes and decrypts embedded payloads.

### S1159 - DUSTTRAP

DUSTTRAP deobfuscates embedded payloads.

### S1014 - DanBot

DanBot can use a VBA macro to decode its payload prior to installation and execution.

### S1111 - DarkGate

DarkGate installation includes binary code stored in a file located in a hidden directory, such as <code>shell.txt</code>, that is decrypted then executed. DarkGate uses hexadecimal-encoded shellcode payloads during installation that are called via Windows API <code>CallWindowProc()</code> to decode and then execute.

### S1066 - DarkTortilla

DarkTortilla can decrypt its payload and associated configuration elements using the Rijndael cipher.

### S0673 - DarkWatchman

DarkWatchman has the ability to self-extract as a RAR archive.

### S0354 - Denis

Denis will decrypt important strings used for C&C communication.

### S0547 - DropBook

DropBook can unarchive data downloaded from the C2 to obtain the payload and persistence modules.

### S0502 - Drovorub

Drovorub has de-obsfuscated XOR encrypted payloads in WebSocket messages.

### S0567 - Dtrack

Dtrack has used a decryption routine that is part of an executable physical patch.

### S0024 - Dyre

Dyre decrypts resources needed for targeting the victim.

### S0377 - Ebury

Ebury has verified C2 domain ownership by decrypting the TXT record using an embedded RSA public key.

### S0624 - Ecipekac

Ecipekac has the ability to decrypt fileless loader modules.

### S0554 - Egregor

Egregor has been decrypted before execution.

### S1247 - Embargo

Embargo has utilized MDeployer to decrypt two payloads that contain MS4Killer toolkit b.cache and the Embargo ransomware executable a.cache with a hardcoded RC4 key `wlQYLoPCil3niI7x8CvR9EtNtL/aeaHrZ23LP3fAsJogVTIzdnZ5Pi09ZVeHFkiB`.

### S0367 - Emotet

Emotet has used a self-extracting RAR file to deliver modules to victims. Emotet has also extracted embedded executables from files using hard-coded buffer offsets.

### S0634 - EnvyScout

EnvyScout can deobfuscate and write malicious ISO files to disk.

### S0401 - Exaramel for Linux

Exaramel for Linux can decrypt its configuration file.

### S1179 - Exbyte

Exbyte decodes and decrypts data stored in the configuration file with a key provided on the command line during execution.

### S0361 - Expand

Expand can be used to decompress a local or remote CAB file into an executable.

### S0618 - FIVEHANDS

FIVEHANDS has the ability to decrypt its payload prior to execution.

### S1120 - FRAMESTING

FRAMESTING can decompress data received within `POST` requests.

### S0628 - FYAnti

FYAnti has the ability to decrypt an embedded .NET module.

### S0512 - FatDuke

FatDuke can decrypt AES encrypted C2 communications.

### S0182 - FinFisher

FinFisher extracts and decrypts stage 3 malware, which is stored in encrypted resources.

### S0355 - Final1stspy

Final1stspy uses Python code to deobfuscate base64-encoded strings.

### S0661 - FoggyWeb

FoggyWeb can be decrypted in memory using a Lightweight Encryption Algorithm (LEA)-128 key and decoded using a XOR key.

### S1117 - GLASSTOKEN

GLASSTOKEN has the ability to decode hexadecimal and Base64 C2 requests.

### S0666 - Gelsemium

Gelsemium can decompress and decrypt DLLs and shellcode.

### S0588 - GoldMax

GoldMax has decoded and decrypted the configuration file when executed.

### S0477 - Goopy

Goopy has used a polymorphic decryptor to decrypt itself at runtime.

### S1138 - Gootloader

Gootloader has the ability to decode and decrypt malicious payloads prior to execution.

### S0531 - Grandoreiro

Grandoreiro can decrypt its encrypted internal strings.

### S0690 - Green Lambert

Green Lambert can use multiple custom routines to decrypt strings prior to execution.

### S0632 - GrimAgent

GrimAgent can use a decryption algorithm for strings based on Rotate on Right (RoR) and Rotate on Left (RoL) functionality.

### S1097 - HUI Loader

HUI Loader can decrypt and load files containing malicious payloads.

### S0499 - Hancitor

Hancitor has decoded Base64 encoded URLs to insert a recipient’s name into the filename of the Word document. Hancitor has also extracted executables from ZIP files.

### S0697 - HermeticWiper

HermeticWiper can decompress and copy driver files using `LZCopy`.

### S1249 - HexEval Loader

HexEval Loader has decoded its payload prior to execution.

### S1027 - Heyoka Backdoor

Heyoka Backdoor can decrypt its payload prior to execution.

### S0394 - HiddenWasp

HiddenWasp uses a cipher to implement a decoding function.

### S0601 - Hildegard

Hildegard has decrypted ELF files with AES.

### S0398 - HyperBro

HyperBro can unpack and decrypt its payload prior to execution.

### S1139 - INC Ransomware

INC Ransomware can run `CryptStringToBinaryA` to decrypt base64 content containing its ransom note.

### S0189 - ISMInjector

ISMInjector uses the <code>certutil</code> command to decode a payload file.

### S1022 - IceApple

IceApple can use a Base64-encoded AES key to decrypt tasking.

### S0434 - Imminent Monitor

Imminent Monitor has decoded malware components that are then dropped to the system.

### S0604 - Industroyer

Industroyer decrypts code to connect to a remote C2 server.

### S0260 - InvisiMole

InvisiMole can decrypt, unpack and load a DLL from its resources, or from blobs encrypted with Data Protection API, two-key triple DES, and variations of the XOR cipher.

### S1245 - InvisibleFerret

InvisibleFerret has decoded XOR-encrypted and Base-64-encoded payloads prior to execution.

### S0581 - IronNetInjector

IronNetInjector has the ability to decrypt embedded .NET and PE payloads.

### S1051 - KEYPLUG

KEYPLUG can decode its configuration file to determine C2 protocols.

### S0526 - KGH_SPY

KGH_SPY can decrypt encrypted strings and write them to a newly created folder.

### S0669 - KOCTOPUS

KOCTOPUS has deobfuscated itself before executing its commands.

### S0356 - KONNI

KONNI has used certutil to download and decode base64 encoded strings and has also devoted a custom section to performing all the components of the deobfuscation process.

### S1190 - Kapeka

Kapeka utilizes obfuscated JSON structures for various data storage and configuration management items.

### S0585 - Kerrdown

Kerrdown can decode, decrypt, and decompress multiple layers of shellcode.

### S0487 - Kessel

Kessel has decrypted the binary's configuration once the <code>main</code> function was launched.

### S0641 - Kobalos

Kobalos decrypts strings right after the initial communication, but before the authentication process.

### S0236 - Kwampirs

Kwampirs decrypts and extracts a copy of its main DLL payload when executing.

### S1119 - LIGHTWIRE

LIGHTWIRE can RC4 decrypt and Base64 decode C2 commands.

### S1160 - Latrodectus

Latrodectus has the ability to deobfuscate encrypted strings.

### S0395 - LightNeuron

LightNeuron has used AES and XOR to decrypt configuration files and commands.

### S1186 - Line Dancer

Line Dancer shellcode payloads are base64 encoded when transmitted to compromised devices.

### S0513 - LiteDuke

LiteDuke has the ability to decrypt and decode multiple layers of obfuscation.

### S0681 - Lizar

Lizar has decrypted its configuration data, such as the C2 IP address, ports and other network communication.

### S1199 - LockBit 2.0

LockBit 2.0 can decode scripts and strings in loaded modules.

### S1202 - LockBit 3.0

The LockBit 3.0 payload is decrypted at runtime.

### S0447 - Lokibot

Lokibot has decoded and decrypted its stages multiple times using hard-coded keys to deliver the final payload, and has decoded its server response hex string using XOR.

### S0582 - LookBack

LookBack has a function that decrypts malicious data.

### S0532 - Lucifer

Lucifer can decrypt its C2 address upon execution.

### S1213 - Lumma Stealer

Lumma Stealer has used Base64-encoded content during execution, decoded via PowerShell.

### S1143 - LunarLoader

LunarLoader can deobfuscate files containing the next stages in the infection chain.

### S1142 - LunarMail

LunarMail can decrypt strings to retrieve configuration settings.

### S1141 - LunarWeb

LunarWeb can decrypt strings related to communication configuration using RC4 with a static key.

### S0443 - MESSAGETAP

After checking for the existence of two files, keyword_parm.txt and parm.txt, MESSAGETAP XOR decodes and read the contents of the files.

### S1221 - MOPSLED

MOPSLED can decrypt obfuscated configuration files.

### S1016 - MacMa

MacMa decrypts a downloaded file using AES-128-EBC with a custom delta.

### S0409 - Machete

Machete’s downloaded data is decrypted using AES.

### S1060 - Mafalda

Mafalda can decrypt files and data.

### S1182 - MagicRAT

MagicRAT stores command and control URLs using base64 encoding in the malware's configuration file.

### S1244 - Medusa Ransomware

Medusa Ransomware has decoded XOR encrypted strings prior to execution in memory.

### S0576 - MegaCortex

MegaCortex has used a Base64 key to decode its components.

### S0455 - Metamorfo

Upon execution, Metamorfo has unzipped itself after being downloaded to the system and has performed string decryption.

### S0280 - MirageFox

MirageFox has a function for decrypting data containing C2 configuration information.

### S1122 - Mispadu

Mispadu decrypts its encrypted configuration files prior to execution.

### S1026 - Mongall

Mongall has the ability to decrypt its payload prior to execution.

### S0284 - More_eggs

More_eggs will decode malware components that are then dropped to the system.

### S1047 - Mori

Mori can resolve networking APIs from strings that are ADD-encrypted.

### S0353 - NOKKI

NOKKI uses a unique, custom de-obfuscation technique.

### S0637 - NativeZone

NativeZone can decrypt and decode embedded  Cobalt Strike beacon stage shellcode.

### S0457 - Netwalker

Netwalker's PowerShell script can decode and decrypt multiple layers of obfuscation, leading to the Netwalker DLL being loaded into memory.

### S1147 - Nightdoor

Nightdoor stores network configuration data in a file XOR encoded with the key value of `0x7A`.

### S1100 - Ninja

The Ninja loader component can decrypt and decompress the payload.

### S1170 - ODAgent

ODAgent can Base64-decode and XOR decrypt received C2 commands.

### S0402 - OSX/Shlayer

OSX/Shlayer can base64-decode and AES-decrypt downloaded payloads. Versions of OSX/Shlayer pass encrypted and password-protected code to <code>openssl</code> and then write the payload to the <code>/tmp</code> folder.

### S0352 - OSX_OCEANLOTUS.D

OSX_OCEANLOTUS.D uses a decode routine combining bit shifting and XOR operations with a variable key that depends on the length of the string that was encoded. If the computation for the variable XOR key turns out to be 0, the default XOR key of 0x1B is used. This routine is also referenced as the `rotate` function in reporting.

### S1172 - OilBooster

OilBooster can Base64-decode and XOR-decrypt C2 commands taken from JSON files.

### S0439 - Okrum

Okrum's loader can decrypt the backdoor code, embedded within the loader or within a legitimate PNG file. A custom XOR cipher or RC4 is used for decryption.

### S0052 - OnionDuke

OnionDuke can use a custom decryption algorithm to decrypt strings.

### S0264 - OopsIE

OopsIE concatenates then decompresses multiple resources to load an embedded .Net Framework assembly.

### S0598 - P.A.S. Webshell

P.A.S. Webshell can use a decryption mechanism to process a user supplied password and allow execution.

### S1123 - PITSTOP

PITSTOP can deobfuscate base64 encoded and AES encrypted commands.

### S0223 - POWERSTATS

POWERSTATS can deobfuscate the main backdoor code.

### S0613 - PS1

PS1 can use an XOR key to decrypt a PowerShell loader and payload binary.

### S1228 - PUBLOAD

PUBLOAD has decoded its payload prior to execution.

### S0196 - PUNCHBUGGY

PUNCHBUGGY has used PowerShell to decode base64-encoded assembly.

### S1050 - PcShare

PcShare has decrypted its strings by applying a XOR operation and a decompression using a custom implemented LZM algorithm.

### S1145 - Pikabot

Pikabot decrypts command and control URIs using ADVobfuscator, and decrypts IP addresses and port numbers with a custom algorithm. Other versions of Pikabot decode chunks of stored stage 2 payload content in the initial payload <code>.text</code> section before consolidating them for further execution. Overall LunarMail is associated with multiple encoding and encryption mechanisms to obfuscate the malware's presence and avoid analysis or detection.

### S0517 - Pillowmint

Pillowmint has been decompressed by included shellcode prior to being launched.

### S1031 - PingPull

PingPull can decrypt received data from its C2 server by using AES.

### S0501 - PipeMon

PipeMon can decrypt password-protected executables.

### S0013 - PlugX

PlugX decompresses and decrypts itself using the Microsoft API call RtlDecompressBuffer. PlugX has also decrypted its payloads in memory.

### S0428 - PoetRAT

PoetRAT has used LZMA and base64 libraries to decode obfuscated scripts.

### S0518 - PolyglotDuke

PolyglotDuke can use a custom algorithm to decrypt strings used by the malware.

### S1046 - PowGoop

PowGoop can decrypt PowerShell scripts for execution.

### S1173 - PowerExchange

PowerExchange can decode and decrypt C2 commands received via email.

### S1012 - PowerLess

PowerLess can use base64 and AES ECB decryption prior to execution of downloaded modules.

### S0279 - Proton

Proton uses an encrypted file to store commands and configuration values.

### S0147 - Pteranodon

Pteranodon can decrypt encrypted data strings prior to using them.

### S1032 - PyDCrypt

PyDCrypt has decrypted and dropped the DCSrv payload to disk.

### S0269 - QUADAGENT

QUADAGENT uses AES and a preshared key to decrypt the custom Base64 routine used to encode strings and scripts.

### S1076 - QUIETCANARY

QUIETCANARY can use a custom parsing routine to decode the command codes and additional parameters from the C2 before executing them.

### S0650 - QakBot

QakBot can deobfuscate and re-assemble code strings for execution.

### S1113 - RAPIDPULSE

RAPIDPULSE listens for specific HTTP query parameters in received communications. If specific parameters match, a hard-coded RC4 key is used to decrypt the HTTP query paremter <code>hmacTime</code>. This decrypts to a filename that is then open, read, encrypted with the same RC4 key, base64-encoded, written to standard out, then passed as a response to the HTTP request.

### S0495 - RDAT

RDAT can deobfuscate the base64-encoded and AES-encrypted files downloaded from the C2 server.

### S1219 - REPTILE

The REPTILE launcher component can decrypt kernel module code from a file and load it into memory.

### S0496 - REvil

REvil can decode encrypted strings to enable execution of commands and payloads.

### S0258 - RGDoor

RGDoor decodes Base64 strings and decrypts strings using a custom XOR algorithm.

### S1222 - RIFLESPINE

RIFLESPINE can deobfuscate encrypted files prior to execution on targeted hosts.

### S1150 - ROADSWEEP

ROADSWEEP can decrypt embedded scripts prior to execution.

### S0240 - ROKRAT

ROKRAT can decrypt strings using the victim's hostname as the key.

### S1148 - Raccoon Stealer

Raccoon Stealer uses RC4-encrypted, base64-encoded strings to obfuscate functionality and command and control servers.

### S0565 - Raindrop

Raindrop decrypted its Cobalt Strike payload using an AES-256 encryption algorithm in CBC mode with a unique key per sample.

### S0629 - RainyDay

RainyDay can decrypt its payload via a XOR key.

### S0458 - Ramsay

Ramsay can extract its agent from the body of a malicious document.

### S1212 - RansomHub

RansomHub can use a provided passphrase to decrypt its configuration file.

### S1130 - Raspberry Robin

Raspberry Robin contains several layers of obfuscation to hide malicious code from detection and analysis.

### S1240 - RedLine Stealer

RedLine Stealer has decoded its payload prior to execution.

### S0511 - RegDuke

RegDuke can decrypt strings with a key either stored in the Registry or hardcoded in the code.

### S0375 - Remexi

Remexi decrypts the configuration data using XOR with 25-character keys.

### S0448 - Rising Sun

Rising Sun has decrypted itself using a single-byte XOR scheme. Additionally, Rising Sun can decrypt its configuration data at runtime.

### S0270 - RogueRobin

RogueRobin decodes an embedded executable using base64 and decompresses it.

### S1078 - RotaJakiro

RotaJakiro uses the AES algorithm, bit shifts in a function called `rotate`, and an XOR cipher to decrypt resources required for persistence, process guarding, and file locking. It also performs this same function on encrypted stack strings and the `head` and `key` sections in the network packet structure used for C2 communications.

### S0461 - SDBbot

SDBbot has the ability to decrypt and decompress its payload to enable code execution.

### S1110 - SLIGHTPULSE

SLIGHTPULSE can deobfuscate base64 encoded and RC4 encrypted C2 messages.

### S0390 - SQLRat

SQLRat has scripts that are responsible for deobfuscating additional scripts.

### S1112 - STEADYPULSE

STEADYPULSE can URL decode key/value pairs sent over C2.

### S0562 - SUNSPOT

SUNSPOT decrypts SUNBURST, which was stored in AES128-CBC encrypted blobs.

### S1210 - Sagerunex

Sagerunex uses a custom decryption routine to unpack itself during installation.

### S1018 - Saint Bot

Saint Bot can deobfuscate strings and files for execution.

### S1168 - SampleCheck5000

SampleCheck5000 can decode and decrypt command line strings and files received through C2.

### S1085 - Sardonic

Sardonic can first decrypt with the RC4 algorithm using a hardcoded decryption key before decompressing.

### S0596 - ShadowPad

ShadowPad has decrypted a binary blob to start execution.

### S0140 - Shamoon

Shamoon decrypts ciphertext using an XOR cipher and a base64-encoded string.

### S1019 - Shark

Shark can extract and decrypt downloaded .zip files.

### S0546 - SharpStage

SharpStage has decompressed data received from the C2 server.

### S0444 - ShimRat

ShimRat has decompressed its core DLL using shellcode once an impersonated antivirus component was running on a system.

### S0589 - Sibot

Sibot can decrypt data received from a C2 and save to a file.

### S0610 - SideTwist

SideTwist can decode and decrypt messages received from C2.

### S0623 - Siloscape

Siloscape has decrypted the password of the C2 server with a simple byte by byte XOR. Siloscape also writes both an archive of Tor and the <code>unzip</code> binary to disk from data embedded within the payload using Visual Studio’s Resource Manager.

### S0468 - Skidmap

Skidmap has the ability to download, unpack, and decrypt tar.gz files .

### S0226 - Smoke Loader

Smoke Loader deobfuscates its code.

### S1086 - Snip3

Snip3 can decode its second-stage PowerShell script prior to execution.

### S0615 - SombRAT

SombRAT can run <code>upload</code> to decrypt and upload files from storage.

### S0516 - SoreFang

SoreFang can decode and decrypt exfiltrated data sent to C2.

### S0543 - Spark

Spark has used a custom XOR algorithm to decrypt the payload.

### S1140 - Spica

Upon execution Spica can decode an embedded .pdf and write it to the desktop as a decoy document.

### S1232 - SplatDropper

SplatDropper has decoded XOR encrypted payload.

### S1030 - Squirrelwaffle

Squirrelwaffle has decrypted files and payloads using a XOR-based algorithm.

### S1227 - StarProxy

StarProxy has decrypted network packets using a custom algorithm.

### S0188 - Starloader

Starloader decrypts and executes shellcode from a file called Stars.jps.

### S1200 - StealBit

StealBit can deobfuscate loaded modules prior to execution.

### S1183 - StrelaStealer

StrelaStealer payloads have included strings encrypted via XOR. StrelaStealer JavaScript payloads utilize Base64-encoded payloads that are decoded via certutil to create a malicious DLL file.

### S0603 - Stuxnet

Stuxnet decrypts resources that are loaded into memory and executed.

### S0663 - SysUpdate

SysUpdate can deobfuscate packed binaries in memory.

### S0560 - TEARDROP

TEARDROP was decoded using a custom rolling XOR algorithm to execute a customized Cobalt Strike payload.

### S1223 - THINCRUST

THINCRUST can deobfuscate RSA encrypted C2 commands received through the DEVICEID cookie.

### S1239 - TONESHELL

TONESHELL has decoded its payload prior to execution.

### S0436 - TSCookie

TSCookie has the ability to decrypt, load, and execute a DLL and its resources.

### S0263 - TYPEFRAME

One TYPEFRAME variant decrypts an archive using an RC4 key, then decompresses and installs the decrypted malicious DLL module. Another variant decodes the embedded file by XORing it with the value "0x35".

### S0011 - Taidoor

Taidoor can use a stream cipher to decrypt stings used by the malware.

### S0665 - ThreatNeedle

ThreatNeedle can decrypt its payload using RC4, AES, or one-byte XORing.

### S0678 - Torisma

Torisma has used XOR and Base64 to decode C2 data.

### S0266 - TrickBot

TrickBot decodes the configuration data and modules.

### S0647 - Turian

Turian has the ability to use a XOR decryption key to extract C2 server domains and IP addresses.

### S1164 - UPSTYLE

UPSTYLE encodes its main content prior to loading via Python as base64-encoded blobs.

### S0022 - Uroburos

Uroburos can decrypt command parameters sent through C2 and use unpacking code to extract its packed executable.

### S0386 - Ursnif

Ursnif has used crypto key information stored in the Registry to decrypt Tor clients dropped to disk.

### S0257 - VERMIN

VERMIN decrypts code, strings, and commands to use once it's on the victim's machine.

### S0476 - Valak

Valak has the ability to decode and decrypt downloaded files.

### S0636 - VaporRage

VaporRage can deobfuscate XOR-encoded shellcode prior to execution.

### S0180 - Volgmer

Volgmer deobfuscates its strings and APIs once its executed.

### S1115 - WIREFIRE

WIREFIRE can decode, decrypt, and decompress data received in C2 HTTP `POST` requests.

### S0670 - WarzoneRAT

WarzoneRAT can use XOR 0x45 to decrypt obfuscated code.

### S0612 - WastedLocker

WastedLocker's custom cryptor, CryptOne, used an XOR based algorithm to decrypt the payload.

### S0579 - Waterbear

Waterbear has the ability to decrypt its RC4 encrypted payload for execution.

### S0515 - WellMail

WellMail can decompress scripts received from C2.

### S0514 - WellMess

WellMess can decode and decrypt data received from C2.

### S0689 - WhisperGate

WhisperGate can deobfuscate downloaded files stored in reverse byte order and decrypt embedded resources using multiple XOR operations.

### S0466 - WindTail

WindTail has the ability to decrypt strings using hard-coded AES keys.

### S0430 - Winnti for Linux

Winnti for Linux has decoded XOR encoded strings holding its configuration upon execution.

### S0141 - Winnti for Windows

The Winnti for Windows dropper can decrypt and decompresses a data blob.

### S1065 - Woody RAT

Woody RAT can deobfuscate Base64-encoded strings and scripts.

### S1207 - XLoader

XLoader uses XOR and RC4 algorithms to decrypt payloads and functions. XLoader can be distributed as a self-extracting RAR archive that launches an AutoIT loader.

### S1248 - XORIndex Loader

XORIndex Loader can decode its payload prior to execution.

### S0388 - YAHOYAH

YAHOYAH decrypts downloaded files before execution.

### S0251 - Zebrocy

Zebrocy decodes its secondary payload and writes it to the victim’s machine. Zebrocy also uses AES and XOR to decrypt strings and payloads.

### S0230 - ZeroT

ZeroT shellcode decrypts and decompresses its RC4-encrypted payload.

### S0330 - Zeus Panda

Zeus Panda decrypts strings in the code during the execution process.

### S1013 - ZxxZ

ZxxZ has used a XOR key to decrypt strings.

### S0160 - certutil

certutil has been used to decode binaries hidden inside certificate files as Base64 information.

### S0032 - gh0st RAT

gh0st RAT has decrypted and loaded the gh0st RAT DLL into memory, once the initial dropper executable is launched.

### S1059 - metaMain

metaMain can decrypt and load other modules.

### S0653 - xCaon

xCaon has decoded strings from the C2 server before executing commands.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0051 - APT28 Nearest Neighbor Campaign

During APT28 Nearest Neighbor Campaign, APT28 unarchived data using the GUI version of WinRAR.

### C0046 - ArcaneDoor

ArcaneDoor involved the use of Base64 obfuscated scripts and commands.

### C0017 - C0017

During C0017, APT41 used the DUSTPAN loader to decrypt embedded payloads.

### C0021 - C0021

During C0021, the threat actors deobfuscated encoded PowerShell commands including use of the specific string `'FromBase'+0x40+'String'`, in place of `FromBase64String` which is normally used to decode base64.

### C0001 - Frankenstein

During Frankenstein, the threat actors deobfuscated Base64-encoded commands following the execution of a malicious script, which revealed a small script designed to obtain an additional payload.

### C0044 - Juicy Mix

During Juicy Mix, OilRig used a script to concatenate and deobfuscate encoded strings in Mango.

### C0016 - Operation Dust Storm

During Operation Dust Storm, attackers used VBS code to decode payloads.

### C0006 - Operation Honeybee

During Operation Honeybee, malicious files were decoded prior to execution.

### C0005 - Operation Spalax

For Operation Spalax, the threat actors used a variety of packers and droppers to decrypt malicious payloads.

### C0056 - RedPenguin

During RedPenguin, UNC3886 used malware implants to deobfuscate incoming C2 messages and encoded archives.

### C0058 - SharePoint ToolShell Exploitation

During SharePoint ToolShell Exploitation, threat actors decrypted scripts prior to execution.

### C0024 - SolarWinds Compromise

During the SolarWinds Compromise, APT29 used 7-Zip to decode their Raindrop malware.

### C0037 - Water Curupira Pikabot Distribution

Water Curupira Pikabot Distribution used highly obfuscated JavaScript files as one initial installer for Pikabot.
