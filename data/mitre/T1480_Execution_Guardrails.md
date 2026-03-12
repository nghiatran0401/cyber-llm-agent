# T1480 - Execution Guardrails

**Tactic:** Defense Evasion
**Platforms:** ESXi, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1480

## Description

Adversaries may use execution guardrails to constrain execution or actions based on adversary supplied and environment specific conditions that are expected to be present on the target. Guardrails ensure that a payload only executes against an intended target and reduces collateral damage from an adversary’s campaign. Values an adversary can provide about a target system or environment to use as guardrails may include specific network share names, attached physical devices, files, joined Active Directory (AD) domains, and local/external IP addresses.

Guardrails can be used to prevent exposure of capabilities in environments that are not intended to be compromised or operated within. This use of guardrails is distinct from typical Virtualization/Sandbox Evasion. While use of Virtualization/Sandbox Evasion may involve checking for known sandbox values and continuing with execution only if there is no match, the use of guardrails will involve checking for an expected target-specific value and only continuing with execution if there is such a match.

Adversaries may identify and block certain user-agents to evade defenses and narrow the scope of their attack to victims and platforms on which it will be most effective. A user-agent self-identifies data such as a user's software application, operating system, vendor, and version. Adversaries may check user-agents for operating system identification and then only serve malware for the exploitable software while ignoring all other operating systems.

## Detection

### Detection Analytics

**Analytic 1551**

Windows environmental validation behavioral chain: (1) Rapid system discovery reconnaissance through WMI queries, registry enumeration, and network share discovery, (2) Environment-specific artifact collection (hostname, domain, IP addresses, installed software, hardware identifiers), (3) Cryptographic operations or conditional logic based on collected environmental values, (4) Selective payload execution contingent on environmental validation results, (5) Temporal correlation between discovery activities and subsequent execution or network communication

**Analytic 1552**

Linux environmental validation behavioral chain: (1) Intensive system enumeration through command execution (uname, hostname, ifconfig, lsblk, mount), (2) File system reconnaissance targeting specific paths, network configurations, and installed packages, (3) Process and user enumeration to validate target environment characteristics, (4) Conditional script execution or binary activation based on environmental criteria, (5) Network connectivity validation and external IP address resolution for geolocation verification

**Analytic 1553**

macOS environmental validation behavioral chain: (1) System profiling through system_profiler, sysctl, and hardware discovery commands, (2) Network interface and configuration enumeration for geolocation and network environment validation, (3) Application installation and version discovery for software environment fingerprinting, (4) Security feature detection (SIP, Gatekeeper, XProtect status), (5) Conditional payload execution based on macOS-specific environmental criteria and System Integrity Protection bypass validation

**Analytic 1554**

ESXi hypervisor environmental validation behavioral chain: (1) Virtual machine inventory and configuration enumeration through vim-cmd and esxcli commands, (2) Host hardware and network configuration discovery for hypervisor environment validation, (3) Datastore and storage configuration reconnaissance, (4) vCenter connectivity and cluster membership validation, (5) Selective malware deployment based on virtualization infrastructure characteristics and target VM validation


## Mitigations

### M1055 - Do Not Mitigate

Execution Guardrails likely should not be mitigated with preventative controls because it may protect unintended targets from being compromised. If targeted, efforts should be focused on preventing adversary tools from running earlier in the chain of activity and on identifying subsequent malicious behavior if compromised.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1194 - Akira _v2

Akira _v2 will fail to execute if the targeted `/vmfs/volumes/` path does not exist or is not defined.

### S0504 - Anchor

Anchor can terminate itself if specific execution flags are not present.

### S1133 - Apostle

Apostle's ransomware variant requires that a base64-encoded argument is passed when executed, that is used as the Public Key for subsequent encryption operations. If Apostle is executed without this argument, it automatically runs a self-delete function.

### S1184 - BOLDMOVE

BOLDMOVE verifies it is executing from a specific path during execution.

### S1161 - BPFDoor

BPFDoor creates a zero byte PID file at `/var/run/haldrund.pid`. BPFDoor uses this file to determine if it is already running on a system to ensure only one instance is executing at a time.

### S0570 - BitPaymer

BitPaymer compares file names and paths to a list of excluded names and directory names during encryption.

### S1180 - BlackByte Ransomware

BlackByte Ransomware creates a mutex value with a hard-coded name, and terminates if that mutex already exists on the victim system. BlackByte Ransomware checks the system language to see if it matches one of a list of hard-coded values; if a match is found, the malware will terminate.

### S0635 - BoomBox

BoomBox can check its current working directory and for the presence of a specific file and terminate if specific values are not found.

### S1149 - CHIMNEYSWEEP

CHIMNEYSWEEP can execute a task which leads to execution if it finds a process name containing “creensaver.”

### S1052 - DEADEYE

DEADEYE can ensure it executes only on intended systems by identifying the victim's volume serial number, hostname, and/or DNS domain.

### S1111 - DarkGate

DarkGate uses per-victim links for hosting malicious archives, such as ZIP files, in services such as SharePoint to prevent other entities from retrieving them.

### S0634 - EnvyScout

EnvyScout can call <code>window.location.pathname</code> to ensure that embedded files are being executed from the C: drive, and will terminate if they are not.

### S1179 - Exbyte

Exbyte checks for the presence of a configuration file before completing execution.

### S1185 - LightSpy

On macOS, LightSpy checks the existence of a process identification number (PID) file, `/Users/Shared/irc.pid`, to verify if LightSpy is currently running.

### S1199 - LockBit 2.0

LockBit 2.0 will not execute on hosts where the system language is set to a language spoken in the Commonwealth of Independent States region.

### S1202 - LockBit 3.0

LockBit 3.0 can make execution dependent on specific parameters including a unique passphrase and the system language of the targeted host not being found on a set exclusion list.

### S1143 - LunarLoader

LunarLoader can use the DNS domain name of a compromised host to create a decryption key to ensure a malicious payload can only execute against the intended targets.

### S0637 - NativeZone

NativeZone can check for the presence of KM.EkeyAlmaz1C.dll and will halt execution unless it is in the same directory as the rest of the malware's components.

### S1242 - Qilin

Qilin can require a specific password to be passed by command-line argument during execution which must match a pre-defined value in the configuration in order for it to continue execution.

### S1150 - ROADSWEEP

ROADSWEEP requires four command line arguments to execute correctly, otherwise it will produce a message box and halt execution.

### S1212 - RansomHub

RansomHub will terminate without proceeding to encryption if the infected machine is on a list of allowlisted machines specified in its configuration.

### S1130 - Raspberry Robin

Raspberry Robin will check for the presence of several security products on victim machines and will avoid UAC bypass mechanisms if they are identified. Raspberry Robin can use specific cookie values in HTTP requests to command and control infrastructure to validate that requests for second stage payloads originate from the initial downloader script.

### S1240 - RedLine Stealer

RedLine Stealer has built in settings to not operate based on geolocation or country of the victim host.

### S0562 - SUNSPOT

SUNSPOT only replaces SolarWinds Orion source code if the MD5 checksums of both the original source code file and backdoored replacement source code match hardcoded values.

### S1210 - Sagerunex

Sagerunex uses a "servicemain" function to verify its environment to ensure it can only be executed as a service, as well as the existence of a configuration file in a specified directory.

### S1178 - ShrinkLocker

ShrinkLocker will exit its "main" function if the victim domain name does not match provided criteria.

### S1035 - Small Sieve

Small Sieve can only execute correctly if the word `Platypus` is passed to it on the command line.

### S1200 - StealBit

StealBit will execute an empty infinite loop if it detects it is being run in the context of a debugger.

### S1183 - StrelaStealer

StrelaStealer variants only execute if the keyboard layout or language matches a set list of variables.

### S0603 - Stuxnet

Stuxnet checks for specific operating systems on 32-bit machines, Registry keys, and dates for vulnerabilities, and will exit execution if the values are not met.

### S1239 - TONESHELL

TONESHELL has an exception handler that executes when ESET antivirus applications `ekrn.exe` and `egui.exe` are not found and directly injects its code into waitfor.exe using Native Windows API including `WriteProcessMemory` and `CreateRemoteThreadEx`.

### S0678 - Torisma

Torisma is only delivered to a compromised host if the victim's IP address is on an allow-list.

### S0636 - VaporRage

VaporRage has the ability to check for the presence of a specific DLL and terminate if it is not found.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0047 - RedDelta Modified PlugX Infection Chain Operations

Mustang Panda included the use of Cloudflare geofencing mechanisms to limit payload download activity during RedDelta Modified PlugX Infection Chain Operations.
