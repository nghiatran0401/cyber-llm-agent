# T1036 - Masquerading

**Tactic:** Defense Evasion
**Platforms:** Containers, ESXi, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1036

## Description

Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. This may include manipulating file metadata, tricking users into misidentifying the file type, and giving legitimate task or service names.

Renaming abusable system utilities to evade security monitoring is also a form of Masquerading.

## Detection

### Detection Analytics

**Analytic 0355**

Adversary renames LOLBINs or deploys binaries with spoofed file names, internal PE metadata, or misleading icons to appear legitimate. File creation is followed by execution or service registration inconsistent with known usage.

**Analytic 0356**

Adversary drops renamed binaries in uncommon directories (e.g., /tmp, /dev/shm) or uses special characters in names (e.g., trailing space, Unicode RLO). Execution or cronjob registration follows shortly after file drop.

**Analytic 0357**

Adversary creates disguised launch daemons or apps with misleading names and bundle metadata (e.g., Info.plist values inconsistent with binary path or icon). Launch is correlated with user logon or persistence setup.

**Analytic 0358**

Adversary uses renamed container images, injects files into containers with misleading names or metadata (e.g., renamed system binaries), and executes them during startup or scheduled jobs.

**Analytic 0359**

Adversary places scripts or binaries with misleading names in /etc/rc.local.d or /var/spool/cron, or registers services with legitimate-sounding names not present in default ESXi builds.


## Mitigations

### M1049 - Antivirus/Antimalware

Anti-virus can be used to automatically quarantine suspicious files.

### M1047 - Audit

Audit user accounts to ensure that each one has a defined purpose.

### M1040 - Behavior Prevention on Endpoint

Implement security controls on the endpoint, such as a Host Intrusion Prevention System (HIPS), to identify and prevent execution of potentially malicious files (such as those with mismatching file signatures).

### M1045 - Code Signing

Require signed binaries.

### M1038 - Execution Prevention

Use tools that restrict program execution via application control by attributes other than file name for common operating system utilities that are needed.

### M1022 - Restrict File and Directory Permissions

Use file system access controls to protect folders such as C:\\Windows\\System32.

### M1018 - User Account Management

Consider defining and enforcing a naming convention for user accounts to more easily spot generic account names that do not fit the typical schema.

### M1017 - User Training

Train users not to open email attachments or click unknown links (URLs). Such training fosters more secure habits within your organization and will limit many of the risks.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0622 - AppleSeed

AppleSeed can disguise JavaScript files as PDFs.

### S1246 - BeaverTail

BeaverTail has masqueraded as MiroTalk installation packages: “MiroTalk.dmg” for macOS and “MiroTalk.msi” for Windows, and has included login GUIs with MiroTalk themes.

### S0268 - Bisonal

Bisonal dropped a decoy payload with a .jpg extension that contained a malicious Visual Basic script.

### S0635 - BoomBox

BoomBox has the ability to mask malicious data strings as PDF files.

### S0497 - Dacls

The Dacls Mach-O binary has been disguised as a .nib file.

### S1111 - DarkGate

DarkGate can masquerade as pirated media content for initial delivery to victims.

### S1066 - DarkTortilla

DarkTortilla's payload has been renamed `PowerShellInfo.exe`.

### S0673 - DarkWatchman

DarkWatchman has used an icon mimicking a text file to mask a malicious executable.

### S0634 - EnvyScout

EnvyScout has used folder icons for malicious files to lure victims into opening them.

### S0696 - Flagpro

Flagpro can download malicious files with a .tmp extension and append them with .exe prior to execution.

### S0661 - FoggyWeb

FoggyWeb can masquerade the output of C2 commands as a fake, but legitimately formatted WebP file.

### S1015 - Milan

Milan has used an executable named `companycatalogue` to appear benign.

### S0637 - NativeZone

NativeZone has, upon execution, displayed a message box that appears to be related to a Ukrainian electronic document management system.

### S0368 - NotPetya

NotPetya drops PsExec with the filename dllhost.dat.

### S0453 - Pony

Pony has used the Adobe Reader icon for the downloaded file to look more trustworthy.

### S1046 - PowGoop

PowGoop has disguised a PowerShell script as a .dat file (goopdate.dat).

### S0662 - RCSession

RCSession has used a file named English.rtf to appear benign on victim hosts.

### S0148 - RTM

RTM has been delivered as archived Windows executable files masquerading as PDF documents.

### S0565 - Raindrop

Raindrop was built to include a modified version of 7-Zip source code (including associated export names) and Far Manager source code.

### S0458 - Ramsay

Ramsay has masqueraded as a JPG image file.

### S1240 - RedLine Stealer

RedLine Stealer malware has masqueraded as legitimate software such as "PDF Converter Software" which has been distributed through poisoned search engine results often resembling legitimate software lures with the combination of typo squatted domains.

### S0446 - Ryuk

Ryuk can create .dll files that actually contain a Rich Text File format document.

### S1018 - Saint Bot

Saint Bot has renamed malicious binaries as `wallpaper.mp4` and `slideshow.mp4` to avoid detection.

### S0615 - SombRAT

SombRAT can use a legitimate process name to hide itself.

### S1183 - StrelaStealer

StrelaStealer PE executable payloads have used uncommon but legitimate extensions such as `.com` instead of `.exe`.

### S0682 - TrailBlazer

TrailBlazer has used filenames that match the name of the compromised system in attempt to avoid detection.

### S0266 - TrickBot

The TrickBot downloader has used an icon to appear as a Microsoft Word document.

### S1164 - UPSTYLE

UPSTYLE has masqueraded filenames using examples such as `update.py`.

### S0689 - WhisperGate

WhisperGate has been disguised as a JPG extension to avoid detection as a malicious PE file.

### S0466 - WindTail

WindTail has used icons mimicking MS Office files to mask payloads.

### S0658 - XCSSET

XCSSET installs malicious application bundles that mimic native macOS apps, such as Safari, by using the legitimate app’s icon and customizing the `Info.plist` to match expected metadata.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0046 - ArcaneDoor

ArcaneDoor involved the use of digital certificates on adversary-controlled network infrastructure that mimicked the formatting used by legitimate Cisco ASA appliances.

### C0015 - C0015

During C0015, the threat actors named a binary file `compareForfor.jpg` to disguise it as a JPG file.

### C0018 - C0018

During C0018, AvosLocker was disguised using the victim company name as the filename.

### C0035 - KV Botnet Activity

KV Botnet Activity involves changing process filename to <code>pr_set_mm_exe_file</code> and process name to <code>pr_set_name</code> during later infection stages.

### C0016 - Operation Dust Storm

For Operation Dust Storm, the threat actors disguised some executables as JPG files.

### C0006 - Operation Honeybee

During Operation Honeybee, the threat actors modified the MaoCheng dropper so its icon appeared as a Word document.

### C0059 - Salesforce Data Exfiltration

During Salesforce Data Exfiltration, threat actors used voice calls to socially engineer victims into authorizing a modified version of the Salesforce Data Loader app.
