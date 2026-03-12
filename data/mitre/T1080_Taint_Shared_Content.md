# T1080 - Taint Shared Content

**Tactic:** Lateral Movement
**Platforms:** Linux, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1080

## Description

Adversaries may deliver payloads to remote systems by adding content to shared storage locations, such as network drives or internal code repositories. Content stored on network drives or in other shared locations may be tainted by adding malicious programs, scripts, or exploit code to otherwise valid files. Once a user opens the shared tainted content, the malicious portion can be executed to run the adversary's code on a remote system. Adversaries may use tainted shared content to move laterally.

A directory share pivot is a variation on this technique that uses several other techniques to propagate malware when users access a shared network directory. It uses Shortcut Modification of directory .LNK files that use Masquerading to look like the real directories, which are hidden through Hidden Files and Directories. The malicious .LNK-based directories have an embedded command that executes the hidden malware file in the directory and then opens the real intended directory so that the user's expected action still occurs. When used with frequently used network directories, the technique may result in frequent reinfections and broad access to systems and potentially to new and higher privileged accounts.

Adversaries may also compromise shared network directories through binary infections by appending or prepending its code to the healthy binary on the shared network directory. The malware may modify the original entry point (OEP) of the healthy binary to ensure that it is executed before the legitimate code. The infection could continue to spread via the newly infected file when it is executed by a remote system. These infections may target both binary and non-binary formats that end with extensions including, but not limited to, .EXE, .DLL, .SCR, .BAT, and/or .VBS.

## Detection

### Detection Analytics

**Analytic 1298**

Detects adversary tampering of shared directories via file drops (e.g., malicious LNK, EXE, VBS) followed by user execution or suspicious network activity.

**Analytic 1299**

Detects script or binary modification within shared NFS/SMB directories followed by process execution from those paths.

**Analytic 1300**

Detects modification of shared network folders via .app bundles or scripting files with hidden extensions (e.g., double extensions like docx.app).

**Analytic 1301**

Detects upload of malicious or unusual file types into cloud-shared folders, followed by user downloads or interactions.

**Analytic 1302**

Detects embedded macros or scripts added to shared documents or use of external references to execute code.


## Mitigations

### M1049 - Antivirus/Antimalware

Anti-virus can be used to automatically quarantine suspicious files.

### M1038 - Execution Prevention

Identify potentially malicious software that may be used to taint content or may result from it and audit and/or block the unknown programs by using application control tools, like AppLocker, or Software Restriction Policies where appropriate.

### M1050 - Exploit Protection

Use utilities that detect or mitigate common features used in exploitation, such as the Microsoft Enhanced Mitigation Experience Toolkit (EMET).

### M1022 - Restrict File and Directory Permissions

Protect shared folders by minimizing users who have write access.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0575 - Conti

Conti can spread itself by infecting other remote machines via network shared drives.

### S0132 - H1N1

H1N1 has functionality to copy itself to network shares.

### S0260 - InvisiMole

InvisiMole can replace legitimate software or documents in the compromised network with their trojanized versions, in an attempt to propagate itself within the network.

### S0133 - Miner-C

Miner-C copies itself into the public folder of Network Attached Storage (NAS) devices and infects new victims who open the file.

### S0458 - Ramsay

Ramsay can spread itself by infecting other portable executable files on networks shared drives.

### S0603 - Stuxnet

Stuxnet infects remote servers via network shares and by infecting WinCC database views with malicious code.

### S0386 - Ursnif

Ursnif has copied itself to and infected files in network drives for propagation.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
