# T1554 - Compromise Host Software Binary

**Tactic:** Persistence
**Platforms:** ESXi, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1554

## Description

Adversaries may modify host software binaries to establish persistent access to systems. Software binaries/executables provide a wide range of system commands or services, programs, and libraries. Common software binaries are SSH clients, FTP clients, email clients, web browsers, and many other user or server applications.

Adversaries may establish persistence though modifications to host software binaries. For example, an adversary may replace or otherwise infect a legitimate application binary (or support files) with a backdoor. Since these binaries may be routinely executed by applications or the user, the adversary can leverage this for persistent access to the host. An adversary may also modify a software binary such as an SSH client in order to persistently collect credentials during logins (i.e., Modify Authentication Process).

An adversary may also modify an existing binary by patching in malicious functionality (e.g., IAT Hooking/Entry point patching) prior to the binary’s legitimate execution. For example, an adversary may modify the entry point of a binary to point to malicious code patched in by the adversary before resuming normal execution flow.

After modifying a binary, an adversary may attempt to Impair Defenses by preventing it from updating (e.g., via the `yum-versionlock` command or `versionlock.list` file in Linux systems that use the yum package manager).

## Detection

### Detection Analytics

**Analytic 0949**

Monitors for unexpected modifications of system or application binaries, particularly signed executables. Correlates file write events with subsequent unsigned or anomalously signed process execution, and checks for tampered binaries outside normal patch cycles.

**Analytic 0950**

Detects modification of system or application binaries by monitoring /usr/bin, /bin, and other privileged directories. Correlates file integrity monitoring (FIM) events with unexpected process executions or service restarts.

**Analytic 0951**

Monitors binary modification in /Applications and system library paths. Detects unsigned or improperly signed binaries executed after modification. Tracks Gatekeeper or notarization bypass attempts tied to modified binaries.

**Analytic 0952**

Detects unauthorized modification of host binaries, modules, or services within ESXi. Correlates tampered files with subsequent unexpected service behavior or malicious module load attempts.


## Mitigations

### M1045 - Code Signing

Ensure all application component binaries are signed by the correct application developers.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1136 - BFG Agonizer

BFG Agonizer uses DLL unhooking to remove user mode inline hooks that security solutions often implement. BFG Agonizer also uses IAT unhooking to remove user-mode IAT hooks that security solutions also use.

### S1184 - BOLDMOVE

BOLDMOVE contains a watchdog-like feature that monitors a particular file for modification. If modification is detected, the legitimate file is backed up and replaced with a trojanized file to allow for persistence through likely system upgrades.

### S1118 - BUSHWALK

BUSHWALK can embed into the legitimate `querymanifest.cgi` file on compromised Ivanti Connect Secure VPNs.

### S0486 - Bonadan

Bonadan has maliciously altered the OpenSSH binary on targeted systems to create a backdoor.

### S0377 - Ebury

Ebury modifies the `keyutils` library to add malicious behavior to the OpenSSH client and the curl library.

### S1120 - FRAMESTING

FRAMESTING can embed itself in the CAV Python package of an Ivanti Connect Secure VPN located in `/home/venv3/lib/python3.6/site-packages/cav-0.1-py3.6.egg/cav/api/resources/category.py.`

### S0604 - Industroyer

Industroyer has used a Trojanized version of the Windows Notepad application for an additional backdoor persistence mechanism.

### S0487 - Kessel

Kessel has maliciously altered the OpenSSH binary on targeted systems to create a backdoor.

### S0641 - Kobalos

Kobalos replaced the SSH client with a trojanized SSH client to steal credentials on compromised systems.

### S1119 - LIGHTWIRE

LIGHTWIRE can imbed itself into the legitimate `compcheckresult.cgi` component of Ivanti Connect Secure VPNs to enable command execution.

### S1121 - LITTLELAMB.WOOLTEA

LITTLELAMB.WOOLTEA can append malicious components to the `tmp/tmpmnt/bin/samba_upgrade.tar` archive inside the factory reset partition in attempt to persist post reset.

### S1104 - SLOWPULSE

SLOWPULSE is applied in compromised environments through modifications to legitimate Pulse Secure files.

### S0595 - ThiefQuest

ThiefQuest searches through the <code>/Users/</code> folder looking for executable files. For each executable, ThiefQuest prepends a copy of itself to the beginning of the file. When the file is executed, the ThiefQuest code is executed first. ThiefQuest creates a hidden file, copies the original target executable to the file, then executes the new hidden file to maintain the appearance of normal behavior.

### S1116 - WARPWIRE

WARPWIRE can embed itself into a legitimate file on compromised Ivanti Connect Secure VPNs.

### S1115 - WIREFIRE

WIREFIRE can modify the `visits.py` component of Ivanti Connect Secure VPNs for file download and arbitrary command execution.

### S0658 - XCSSET

XCSSET uses a malicious browser application to replace the legitimate browser in order to continuously capture credentials, monitor web traffic, and download additional modules.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0025 - 2016 Ukraine Electric Power Attack

During the 2016 Ukraine Electric Power Attack, Sandworm Team used a trojanized version of Windows Notepad to add a layer of persistence for Industroyer.

### C0029 - Cutting Edge

During Cutting Edge, threat actors trojanized legitimate files in Ivanti Connect Secure appliances with malicious code.

### C0056 - RedPenguin

During RedPenguin, UNC3886 peformed a local memory patching attack to modify the snmpd and mgd Junos OS daemons.
