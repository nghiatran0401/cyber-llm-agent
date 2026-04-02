# T1560 - Archive Collected Data

**Tactic:** Collection
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1560

## Description

An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network. Encryption can be used to hide information that is being exfiltrated from detection or make exfiltration less conspicuous upon inspection by a defender.

Both compression and encryption are done prior to exfiltration, and can be performed using a utility, 3rd party library, or custom method.

## Detection

### Detection Analytics

**Analytic 1458**

Detects adversarial archiving of files prior to exfiltration by correlating execution of compression/encryption utilities (e.g., makecab.exe, rar.exe, 7z.exe, powershell Compress-Archive) with subsequent creation of large compressed or encrypted files. Identifies abnormal process lineage involving crypt32.dll usage, command-line arguments invoking compression switches, and file write operations to temporary or staging directories.

**Analytic 1459**

Detects adversarial archiving activity through invocation of utilities like tar, gzip, bzip2, or openssl used in non-administrative or unusual contexts. Correlates command execution patterns with file creation of compressed/encrypted outputs in staging directories (e.g., /tmp, /var/tmp).

**Analytic 1460**

Detects use of macOS-native archiving or encryption tools (zip, ditto, hdiutil) for staging collected data. Identifies unexpected invocation of archive utilities by Office apps, browsers, or background daemons. Correlates file creation of .zip/.dmg containers with process lineage anomalies.


## Mitigations

### M1047 - Audit

System scans can be performed to identify unauthorized archival utilities.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0045 - ADVSTORESHELL

ADVSTORESHELL encrypts with the 3DES algorithm and a hardcoded key prior to exfiltration.

### S0331 - Agent Tesla

Agent Tesla can encrypt data with 3DES before sending it over to a C2 server.

### S0622 - AppleSeed

AppleSeed has compressed collected data before exfiltration.

### S0456 - Aria-body

Aria-body has used ZIP to compress data gathered on a compromised host.

### S0657 - BLUELIGHT

BLUELIGHT can zip files before exfiltration.

### S0093 - Backdoor.Oldrea

Backdoor.Oldrea writes collected data to a temporary file in an encrypted form before exfiltration to a C2 server.

### S0521 - BloodHound

BloodHound can compress data collected by its SharpHound ingestor into a ZIP file to be written to disk.

### S1039 - Bumblebee

Bumblebee can compress data stolen from the Registry and volume shadow copies prior to exfiltration.

### S0454 - Cadelspy

Cadelspy has the ability to compress stolen data into a .cab file.

### S0667 - Chrommme

Chrommme can encrypt and store on disk collected data before exfiltration.

### S0187 - Daserf

Daserf hides collected data in password-protected .rar archives.

### S0567 - Dtrack

Dtrack packs collected data into a password protected archive.

### S0363 - Empire

Empire can ZIP directories on the target system.

### S0091 - Epic

Epic encrypts collected data using a public key framework before sending it over the C2 channel. Some variants encrypt the collected data with AES and encode it with base64 before transmitting it to the C2 server.

### S0343 - Exaramel for Windows

Exaramel for Windows automatically encrypts files before sending them to the C2 server.

### S0267 - FELIXROOT

FELIXROOT encrypts collected data with AES and Base64 and then sends it to the C2 server.

### S0249 - Gold Dragon

Gold Dragon encrypts data using Base64 before being sent to the command and control server.

### S1206 - JumbledPath

JumbledPath can compress and encrypt exfiltrated packet captures from targeted devices.

### S0356 - KONNI

KONNI has encrypted data and files prior to exfiltration.

### S0487 - Kessel

Kessel can RC4-encrypt credentials before sending to the C2.

### S0395 - LightNeuron

LightNeuron contains a function to encrypt and store emails that it collects.

### S0681 - Lizar

Lizar has encrypted data before sending it to the server.

### S1101 - LoFiSe

LoFiSe can collect files into password-protected ZIP-archives for exfiltration.

### S0010 - Lurid

Lurid can compress data before sending it.

### S0409 - Machete

Machete stores zipped files with profile data from installed web browsers.

### S0198 - NETWIRE

NETWIRE has the ability to compress archived screenshots.

### S0517 - Pillowmint

Pillowmint has encrypted stolen credit card information with AES and further encoded it with Base64.

### S1012 - PowerLess

PowerLess can encrypt browser database files prior to exfiltration.

### S0113 - Prikormka

After collecting documents from removable media, Prikormka compresses the collected files, and encrypts it with Blowfish.

### S0279 - Proton

Proton zips up files before exfiltrating them.

### S1148 - Raccoon Stealer

Raccoon Stealer archives collected system information in a text f ile, `System info.txt`, prior to exfiltration.

### S0375 - Remexi

Remexi encrypts and adds all gathered browser data into files for upload to C2.

### S0253 - RunningRAT

RunningRAT contains code to compress files.

### S0445 - ShimRatReporter

ShimRatReporter used LZ compression to compress initial reconnaissance reports before sending to the C2.

### S1140 - Spica

Spica can archive collected documents for exfiltration.

### S0586 - TAINTEDSCRIBE

TAINTEDSCRIBE has used <code>FileReadZipSend</code> to compress a file and send to C2.

### S1196 - Troll Stealer

Troll Stealer compresses stolen data prior to exfiltration.

### S0257 - VERMIN

VERMIN encrypts the collected files using 3-DES.

### S0515 - WellMail

WellMail can archive files on the compromised host.

### S0658 - XCSSET

XCSSET will compress entire <code>~/Desktop</code> folders excluding all <code>.git</code> folders, but only if the total data size is under 200MB.

### S0251 - Zebrocy

Zebrocy  has used a method similar to RC4 as well as AES for encryption and hexadecimal for encoding data before exfiltration.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
