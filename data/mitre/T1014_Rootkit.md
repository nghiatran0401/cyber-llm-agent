# T1014 - Rootkit

**Tactic:** Defense Evasion
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1014

## Description

Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components. Rootkits are programs that hide the existence of malware by intercepting/hooking and modifying operating system API calls that supply system information. 

Rootkits or rootkit enabling functionality may reside at the user or kernel level in the operating system or lower, to include a hypervisor or System Firmware. Rootkits have been seen for Windows, Linux, and Mac OS X systems.

Rootkits that reside or modify boot sectors are known as Bootkits and specifically target the boot process of the operating system.

## Detection

### Detection Analytics

**Analytic 1061**

Unauthorized or anomalous loading of kernel-mode drivers or DLLs, concealed services, or abnormal modification of boot components indicative of rootkit activity.

**Analytic 1062**

Abnormal loading of kernel modules, direct tampering with /dev, /proc, or LD_PRELOAD behaviors hiding processes or files.

**Analytic 1063**

Execution of unsigned kernel extensions (KEXTs), tampering with LaunchDaemons, or userspace hooks into system libraries.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1105 - COATHANGER

COATHANGER hooks or replaces multiple legitimate processes and other functions on victim devices.

### S0484 - Carberp

Carberp has used user mode rootkit techniques to remain hidden on the system.

### S0572 - Caterpillar WebShell

Caterpillar WebShell has a module to use a rootkit on a system.

### S0502 - Drovorub

Drovorub has used a kernel module rootkit to hide processes, files, executables, and network artifacts from user space view.

### S0377 - Ebury

Ebury acts as a user land rootkit using the SSH service.

### S0135 - HIDEDRV

HIDEDRV is a rootkit that hides certain operating system artifacts.

### S0040 - HTRAN

HTRAN can install a rootkit to hide network connections from the host OS.

### S0047 - Hacking Team UEFI Rootkit

Hacking Team UEFI Rootkit is a UEFI BIOS rootkit developed by the company Hacking Team to persist remote access software on some targeted systems.

### S0394 - HiddenWasp

HiddenWasp uses a rootkit to hook and implement functions on the system.

### S0009 - Hikit

Hikit is a Rootkit that has been used by Axiom.

### S0601 - Hildegard

Hildegard has modified /etc/ld.so.preload to overwrite readdir() and readdir64().

### S1186 - Line Dancer

Line Dancer can hook both the crash dump process and the Autehntication, Authorization, and Accounting (AAA) functions on compromised machines to evade forensic analysis and authentication mechanisms.

### S0397 - LoJax

LoJax is a UEFI BIOS rootkit deployed to persist remote access software on some targeted systems.

### S1220 - MEDUSA

MEDUSA is a rootkit with command execution and credential logging capabilities.

### S0012 - PoisonIvy

PoisonIvy starts a rootkit from a malicious file dropped to disk.

### S1219 - REPTILE

REPTILE has the ability to hook kernel functions and modify functions data to achieve rootkit functionality such as hiding processes and network connections.

### S0458 - Ramsay

Ramsay has included a rootkit to evade defenses.

### S0468 - Skidmap

Skidmap is a kernel-mode rootkit that has the ability to hook system calls to hide specific files and fake network and CPU-related statistics to make the CPU load of the infected machine always appear low.

### S0603 - Stuxnet

Stuxnet uses a Windows rootkit to mask its binaries and other relevant files.

### S0221 - Umbreon

Umbreon hides from defenders by hooking libc function calls, hiding artifacts that would reveal its presence, such as the user account it creates to provide access and undermining strace, a tool often used to identify malware.

### S0022 - Uroburos

Uroburos can use its kernel module to prevent its host components from being listed by the targeted system's OS and to mediate requests between user mode and concealed components.

### S0670 - WarzoneRAT

WarzoneRAT can include a rootkit to hide processes, files, and startup.

### S0430 - Winnti for Linux

Winnti for Linux has used a modified copy of the open-source userland rootkit Azazel, named libxselinux.so, to hide the malware's operations and network activity.

### S0027 - Zeroaccess

Zeroaccess is a kernel-mode rootkit.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0046 - ArcaneDoor

ArcaneDoor included hooking the `processHostScanReply()` function on victim Cisco ASA devices.

### C0056 - RedPenguin

During RedPenguin, UNC3886 used rootkits such as REPTILE and MEDUSA.
