# T1027 - Obfuscated Files or Information

**Tactic:** Defense Evasion
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1027

## Description

Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses. 

Payloads may be compressed, archived, or encrypted in order to avoid detection. These payloads may be used during Initial Access or later to mitigate detection. Sometimes a user's action may be required to open and Deobfuscate/Decode Files or Information for User Execution. The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. Adversaries may also use compressed or archived scripts, such as JavaScript. 

Portions of files can also be encoded to hide the plain-text strings that would otherwise help defenders with discovery. Payloads may also be split into separate, seemingly benign files that only reveal malicious functionality when reassembled.

Adversaries may also abuse Command Obfuscation to obscure commands executed from payloads or directly via Command and Scripting Interpreter. Environment variables, aliases, characters, and other platform/language specific semantics can be used to evade signature based detections and application control mechanisms.

## Detection

### Detection Analytics

**Analytic 1064**

Correlates script execution or suspicious parent processes with creation or modification of encoded, compressed, or encrypted file formats (e.g., .zip, .7z, .enc) and abnormal command-line syntax or PowerShell obfuscation.

**Analytic 1065**

Detects use of gzip, base64, tar, or openssl in scripts or commands that encode/encrypt files after file staging or system enumeration.

**Analytic 1066**

Monitors use of archive or encryption tools (zip, openssl) tied to user-scripted activity or binaries writing encoded payloads under /Users or /Volumes.

**Analytic 1067**

Identifies transfer of base64, uuencoded, or high-entropy files over HTTP, FTP, or custom protocols in lateral movement or exfiltration streams.

**Analytic 1068**

Detects encoded PowerCLI or Base64-encoded payloads staged via datastore uploads or shell access (e.g., ESXi Shell or backdoored VIBs).


## Mitigations

### M1049 - Antivirus/Antimalware

Anti-virus can be used to automatically detect and quarantine suspicious files. Consider utilizing the Antimalware Scan Interface (AMSI) on Windows 10+ to analyze commands after being processed/interpreted.

### M1047 - Audit

Consider periodic review of common fileless storage locations (such as the Registry or WMI repository) to potentially identify abnormal and malicious data.

### M1040 - Behavior Prevention on Endpoint

On Windows 10+, enable Attack Surface Reduction (ASR) rules to prevent execution of potentially obfuscated payloads.

### M1017 - User Training

Ensure that a finite amount of ingress points to a software deployment system exist with restricted access for those required to allow and enable newly deployed software.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0045 - ADVSTORESHELL

Most of the strings in ADVSTORESHELL are encrypted with an XOR-based algorithm; some strings are also encrypted with 3DES and reversed. API function names are also reversed, presumably to avoid detection in memory.

### S1028 - Action RAT

Action RAT's commands, strings, and domains can be Base64 encoded within the payload.

### S0331 - Agent Tesla

Agent Tesla has had its code obfuscated in an apparent attempt to make analysis difficult. Agent Tesla has used the Rijndael symmetric encryption algorithm to encrypt strings.

### S1025 - Amadey

Amadey has obfuscated strings such as antivirus vendor names, domains, files, and others.

### S0504 - Anchor

Anchor has obfuscated code with stack strings and string encryption.

### S0584 - AppleJeus

AppleJeus has XOR-encrypted collected system information prior to sending to a C2. AppleJeus has also used the open source ADVObfuscation library for its components.

### S0622 - AppleSeed

AppleSeed has the ability to Base64 encode its payload and custom encrypt API calls.

### S0640 - Avaddon

Avaddon has used encrypted strings.

### S1053 - AvosLocker

AvosLocker has used XOR-encoded strings.

### S1226 - BOOKWORM

BOOKWORM has been delivered using self-extracting RAR archives.

### S1161 - BPFDoor

BPFDoor can require a password to activate the backdoor and uses RC4 encryption or static library encryption `libtomcrypt`.

### S1118 - BUSHWALK

BUSHWALK can encrypt the resulting data generated from C2 commands with RC4.

### S0635 - BoomBox

BoomBox can encrypt data using AES prior to exfiltration.

### S0651 - BoxCaon

BoxCaon used the "StackStrings" obfuscation technique to hide malicious functionalities.

### S1063 - Brute Ratel C4

Brute Ratel C4 has used encrypted payload files and maintains an encrypted configuration structure in memory.

### S1039 - Bumblebee

Bumblebee has been delivered as password-protected zipped ISO files and used control-flow-flattening to obfuscate the flow of functions.

### S0482 - Bundlore

Bundlore has obfuscated data with base64, AES, RC4, and bz2.

### S0465 - CARROTBALL

CARROTBALL has used a custom base64 alphabet to decode files.

### S1149 - CHIMNEYSWEEP

CHIMNEYSWEEP can use a custom Base64 alphabet to encode an API decryption key.

### S1105 - COATHANGER

COATHANGER can store obfuscated configuration information in the last 56 bytes of the file `/date/.bd.key/preload.so`.

### S0137 - CORESHELL

CORESHELL obfuscates strings using a custom stream cipher.

### S0030 - Carbanak

Carbanak encrypts strings to make analysis more difficult.

### S0335 - Carbon

Carbon encrypts configuration files and tasks for the malware to complete using CAST-128 algorithm.

### S0660 - Clambling

The Clambling executable has been obfuscated when dropped on a compromised host.

### S0154 - Cobalt Strike

Cobalt Strike can hash functions to obfuscate calls to the Windows API and use a public/private key pair to encrypt Beacon session metadata.

### S0369 - CoinTicker

CoinTicker initially downloads a hidden encoded file.

### S0126 - ComRAT

ComRAT has encrypted its virtual file system using AES-256 in XTS mode.

### S0244 - Comnie

Comnie uses RC4 and Base64 to obfuscate strings.

### S0608 - Conficker

Conficker has obfuscated its code to prevent its removal from host machines.

### S0575 - Conti

Conti can use compiler-based obfuscation for its code, encrypt DLLs, and hide Windows API calls.

### S0625 - Cuba

Cuba has used multiple layers of obfuscation to avoid analysis, including its Base64 encoded payload.

### S0694 - DRATzarus

DRATzarus can be partly encrypted with XOR.

### S1111 - DarkGate

DarkGate uses a hard-coded string as a seed, along with the victim machine hardware identifier and input text, to generate a unique string used as an internal mutex value to evade static detection based on mutexes.

### S1066 - DarkTortilla

DarkTortilla has been obfuscated with the DeepSea .NET and ConfuserEx code obfuscators.

### S0187 - Daserf

Daserf uses encrypted Windows APIs and also encrypts data using the alternative base64+RC4 or the Caesar cipher.

### S0354 - Denis

Denis obfuscates its code and encrypts the API names.

### S0659 - Diavol

Diavol has Base64 encoded the RSA public key used for encrypting files.

### S0384 - Dridex

Dridex's strings are obfuscated using RC4.

### S0502 - Drovorub

Drovorub has used XOR encrypted payloads in WebSocket client to server messages.

### S0062 - DustySky

The DustySky dropper uses a function to obfuscate the name of functions and other parts of the malware.

### S0593 - ECCENTRICBANDWAGON

ECCENTRICBANDWAGON has encrypted strings with RC4.

### S0605 - EKANS

EKANS uses encoded strings in its process kill list.

### S0377 - Ebury

Ebury has obfuscated its strings with a simple XOR encryption with a static key.

### S0624 - Ecipekac

Ecipekac can use XOR, AES, and DES to encrypt loader shellcode.

### S0091 - Epic

Epic heavily obfuscates its code to make analysis more difficult.

### S0512 - FatDuke

FatDuke can use base64 encoding, string stacking, and opaque predicates for obfuscation.

### S0182 - FinFisher

FinFisher is heavily obfuscated in many ways, including through the use of spaghetti code in its functions in an effort to confuse disassembly programs. It also uses a custom XOR algorithm to obfuscate code.

### S0355 - Final1stspy

Final1stspy obfuscates strings with base64 encoding.

### S0696 - Flagpro

Flagpro has been delivered within ZIP or RAR password-protected archived files.

### S1138 - Gootloader

The Gootloader first stage script is obfuscated using random alpha numeric strings.

### S0690 - Green Lambert

Green Lambert has encrypted strings.

### S0632 - GrimAgent

GrimAgent has used Rotate on Right (RoR) and Rotate on Left (RoL) functionality to encrypt strings.

### S0132 - H1N1

H1N1 uses multiple techniques to obfuscate strings, including XOR.

### S0070 - HTTPBrowser

HTTPBrowser's code may be obfuscated through structured exception handling and return-oriented programming.

### S0499 - Hancitor

Hancitor has used Base64 to encode malicious links.

### S0203 - Hydraq

Hydraq uses basic obfuscation in the form of spaghetti code.

### S0189 - ISMInjector

ISMInjector is obfuscated with the off-the-shelf SmartAssembly .NET obfuscator created by red-gate.com.

### S0434 - Imminent Monitor

Imminent Monitor has encrypted the spearphish attachments to avoid detection from email gateways; the debugger also encrypts information before sending to the C2.

### S0604 - Industroyer

Industroyer uses heavily obfuscated code in its Windows Notepad backdoor.

### S0259 - InnaputRAT

InnaputRAT uses an 8-byte XOR key to obfuscate API names and other strings contained in the payload.

### S0260 - InvisiMole

InvisiMole avoids analysis by encrypting all strings, internal files, configuration data and by using a custom executable format.

### S0201 - JPIN

A JPIN uses a encrypted and compressed payload that is disguised as a bitmap within the resource section of the installer.

### S0265 - Kazuar

Kazuar is obfuscated using the open source ConfuserEx protector. Kazuar also obfuscates the name of created files/folders/mutexes and encrypts debug messages written to log files using the Rijndael cipher.

### S0607 - KillDisk

KillDisk uses VMProtect to make reverse engineering the malware more difficult.

### S0641 - Kobalos

Kobalos encrypts all strings using RC4 and bundles all functionality into a single function call.

### S0681 - Lizar

Lizar has obfuscated the fingerprint of the victim system, the local IP address, and the Fowler-Noll-V 1 (FNV-1) hash of the local IP address using an XOR operation. The data is then sent to the C2 server.

### S0447 - Lokibot

Lokibot has obfuscated strings with base64 encoding.

### S1213 - Lumma Stealer

Lumma Stealer has used SmartAssembly to obfuscate .NET payloads.

### S0500 - MCMD

MCMD can Base64 encode output strings prior to sending to C2.

### S0167 - Matryoshka

Matryoshka obfuscates API function names using a substitute cipher combined with Base64 encoding.

### S0449 - Maze

Maze has decrypted strings and other important information during the encryption process. Maze also calls certain functions dynamically to hinder analysis.

### S0051 - MiniDuke

MiniDuke can use control flow flattening to obscure code.

### S0198 - NETWIRE

NETWIRE has used a custom obfuscation algorithm to hide strings including Registry keys, APIs, and DLL names.

### S0353 - NOKKI

NOKKI uses Base64 encoding for strings.

### S0336 - NanoCore

NanoCore’s plugins were obfuscated with Eazfuscater.NET 3.3.

### S1090 - NightClub

NightClub can obfuscate strings using the congruential generator `(LCG): staten+1 = (690069 × staten + 1) mod 232`.

### S0138 - OLDBAIT

OLDBAIT obfuscates internal strings and unpacks them at startup.

### S0264 - OopsIE

OopsIE uses the Confuser protector to obfuscate an embedded .Net Framework assembly used for C2. OopsIE also encodes collected data in hexadecimal format before writing to files on disk and obfuscates strings.

### S0229 - Orz

Some Orz strings are base64 encoded, such as the embedded DLL known as MockDll.

### S0594 - Out1

Out1 has the ability to encode data.

### S0598 - P.A.S. Webshell

P.A.S. Webshell can use encryption and base64 encoding to hide strings and to enforce access control once deployed.

### S0150 - POSHSPY

POSHSPY appends a file signature header (randomly selected from six file types) to encrypted data prior to upload or download.

### S1228 - PUBLOAD

PUBLOAD has obfuscated DLL names using the ror13AddHash32 algorithm.

### S0196 - PUNCHBUGGY

PUNCHBUGGY has hashed most its code's functions and encrypted payloads with base64 and XOR.

### S0197 - PUNCHTRACK

PUNCHTRACK is loaded and executed by a highly obfuscated launcher.

### S0517 - Pillowmint

Pillowmint has obfuscated the AES key used for encryption.

### S0124 - Pisloader

Pisloader obfuscates files by splitting strings into smaller sub-strings and including "garbage" strings that are never used. The malware also uses return-oriented programming (ROP) technique and single-byte XOR to obfuscate data.

### S0013 - PlugX

PlugX can use API hashing and modify the names of strings to evade detection.

### S0428 - PoetRAT

PoetRAT has used a custom encryption scheme for communication between scripts.

### S0012 - PoisonIvy

PoisonIvy hides any strings related to its own indicators of compromise.

### S0518 - PolyglotDuke

PolyglotDuke can custom encrypt strings.

### S0393 - PowerStallion

PowerStallion uses a XOR cipher to encrypt command output written to its OneDrive C2 server.

### S0650 - QakBot

QakBot has hidden code within Excel spreadsheets by turning the font color to white and splitting it across multiple cells.

### S0240 - ROKRAT

ROKRAT can encrypt data prior to exfiltration by using an RSA public key.

### S0148 - RTM

RTM strings, network data, configuration, and modules are encrypted with a modified RC4 algorithm.

### S0458 - Ramsay

Ramsay has base64-encoded its portable executable and hidden itself under a JPG header. Ramsay can also embed information within document footers.

### S1130 - Raspberry Robin

Raspberry Robin uses mixed-case letters for filenames and commands to evade detection.

### S0511 - RegDuke

RegDuke can use control-flow flattening or the commercially available .NET Reactor for obfuscation.

### S0332 - Remcos

Remcos uses RC4 and base64 to obfuscate data, including Registry entries and file paths.

### S0446 - Ryuk

Ryuk can use anti-disassembly and code transformation obfuscation techniques.

### S0461 - SDBbot

SDBbot has the ability to XOR the strings for its installer component with a hardcoded 128 byte key.

### S0063 - SHOTPUT

SHOTPUT is obscured using XOR encoding and appended to a valid GIF file.

### S1104 - SLOWPULSE

SLOWPULSE can hide malicious code in the padding regions between legitimate functions in the Pulse Secure `libdsplibs.so` file.

### S0559 - SUNBURST

SUNBURST obfuscated collected system information using a FNV-1a + XOR algorithm.

### S0562 - SUNSPOT

SUNSPOT encrypted log entries it collected with the stream cipher RC4 using a hard-coded key. It also uses AES128-CBC encrypted blobs for SUNBURST source code and data extracted from the SolarWinds Orion <MsBuild.exe</code> process.

### S1064 - SVCReady

SVCReady can encrypt victim data with an RC4 cipher.

### S1018 - Saint Bot

Saint Bot has been obfuscated to help avoid detection.

### S1099 - Samurai

Samurai can encrypt the names of requested APIs.

### S1085 - Sardonic

Sardonic can use certain ConfuserEx features for obfuscation and can be encoded in a base64 string.

### S0596 - ShadowPad

ShadowPad has encrypted its payload, a virtual file system, and various files.

### S0140 - Shamoon

Shamoon contains base64-encoded strings.

### S0445 - ShimRatReporter

ShimRatReporter encrypted gathered information with a combination of shifting and XOR using a static key.

### S0623 - Siloscape

Siloscape itself is obfuscated and uses obfuscated API calls.

### S0633 - Sliver

Sliver obfuscates configuration and other static files using native Go libraries such as `garble` and `gobfuscate` to inhibit configuration analysis and static detection.

### S1035 - Small Sieve

Small Sieve has the ability to use a custom hex byte swapping encoding scheme combined with an obfuscated Base64 function to protect program strings and Telegram credentials.

### S1086 - Snip3

Snip3 has the ability to obfuscate strings using XOR encryption.

### S0627 - SodaMaster

SodaMaster can use "stackstrings" for obfuscation.

### S0615 - SombRAT

SombRAT can encrypt strings with XOR-based routines and use a custom AES storage format for plugins, configuration, C2 domains, and harvested data.

### S0516 - SoreFang

SoreFang has the ability to encode and RC6 encrypt data sent to C2.

### S0142 - StreamEx

StreamEx obfuscates some commands by using statically programmed fragments of strings when starting a DLL. It also uses a one-byte xor against 0x91 to encode configuration data.

### S1183 - StrelaStealer

StrelaStealer has been distributed in ISO archives. StrelaStealer has been delivered in encrypted, password-protected ZIP archives.

### S0242 - SynAck

SynAck payloads are obfuscated prior to compilation to inhibit analysis and/or reverse engineering.

### S0560 - TEARDROP

TEARDROP created and read from a file with a fake JPG header, and its payload was encrypted with a simple rotating XOR cipher.

### S0467 - TajMahal

TajMahal has used an encrypted Virtual File System to store plugins.

### S0266 - TrickBot

TrickBot uses non-descriptive names to hide functionality.

### S0094 - Trojan.Karagany

Trojan.Karagany can base64 encode and AES-128-CBC encrypt data prior to transmission.

### S0647 - Turian

Turian can use VMProtect for obfuscation.

### S0476 - Valak

Valak has the ability to base64 encode and XOR encrypt strings.

### S0117 - XTunnel

A version of XTunnel introduced in July 2015 obfuscated the binary using opaque predicates and other techniques in a likely attempt to obfuscate it and bypass security products.

### S0283 - jRAT

jRAT’s Java payload is encrypted with AES. Additionally, backdoor files are encrypted using DES as a stream cipher. Later variants of jRAT also incorporated AV evasion methods such as Java bytecode obfuscation via the commercial Allatori obfuscation tool.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0025 - 2016 Ukraine Electric Power Attack

During the 2016 Ukraine Electric Power Attack, Sandworm Team used heavily obfuscated code with Industroyer in its Windows Notepad backdoor.

### C0057 - 3CX Supply Chain Attack

During the 3CX Supply Chain Attack, AppleJeus payloads use AES-256 GCM cipher to encrypt data to include ICONICSTEALER and VEILEDSIGNAL.

### C0015 - C0015

During C0015, the threat actors used Base64-encoded strings.

### C0017 - C0017

During C0017, APT41 broke malicious binaries, including DEADEYE and KEYPLUG, into multiple sections on disk to evade detection.
