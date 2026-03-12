# T1055 - Process Injection

**Tactic:** Defense Evasion, Privilege Escalation
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1055

## Description

Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process. 

There are many different ways to inject code into a process, many of which abuse legitimate functionalities. These implementations exist for every major OS but are typically platform specific. 

More sophisticated samples may perform multiple process injections to segment modules and further evade detection, utilizing named pipes or other inter-process communication (IPC) mechanisms as a communication channel.

## Detection

### Detection Analytics

**Analytic 1399**

Detects process injection by correlating memory manipulation API calls (e.g., VirtualAllocEx, WriteProcessMemory), suspicious thread creation (e.g., CreateRemoteThread), and unusual DLL loads within another process's context.

**Analytic 1400**

Detects ptrace- or memfd-based process injection through audit logs capturing system calls (e.g., ptrace, mmap) targeting running processes along with suspicious file descriptors or memory writes.

**Analytic 1401**

Detects memory-based injection by monitoring `task_for_pid`, `mach_vm_write`, and dylib injection patterns through `DYLD_INSERT_LIBRARIES` or manual memory mapping.


## Mitigations

### M1040 - Behavior Prevention on Endpoint

Some endpoint security solutions can be configured to block some types of process injection based on common sequences of behavior that occur during the injection process. For example, on Windows 10, Attack Surface Reduction (ASR) rules may prevent Office applications from code injection.

### M1026 - Privileged Account Management

Utilize Yama (ex: /proc/sys/kernel/yama/ptrace_scope) to mitigate ptrace based process injection by restricting the use of ptrace to privileged users only. Other mitigation controls involve the deployment of security kernel modules that provide advanced access control and process restrictions such as SELinux, grsecurity, and AppArmor.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0469 - ABK

ABK has the ability to inject shellcode into svchost.exe.

### S1074 - ANDROMEDA

ANDROMEDA can inject into the `wuauclt.exe` process to perform C2 actions.

### S0331 - Agent Tesla

Agent Tesla can inject into known, vulnerable binaries on targeted hosts.

### S0438 - Attor

Attor's dispatcher can inject itself into running processes to gain higher privileges and to evade detection.

### S0347 - AuditCred

AuditCred can inject code from files to other running processes.

### S0473 - Avenger

Avenger has the ability to inject shellcode into svchost.exe.

### S1081 - BADHATCH

BADHATCH can inject itself into an existing explorer.exe process by using `RtlCreateUserThread`.

### S0470 - BBK

BBK has the ability to inject shellcode into svchost.exe.

### S0093 - Backdoor.Oldrea

Backdoor.Oldrea injects itself into explorer.exe.

### S0534 - Bazar

Bazar can inject code through calling <code>VirtualAllocExNuma</code>.

### S1181 - BlackByte 2.0 Ransomware

BlackByte 2.0 Ransomware injects into a newly-created `svchost.exe` process prior to device encryption.

### S1039 - Bumblebee

Bumblebee can inject code into multiple processes on infected endpoints.

### S1105 - COATHANGER

COATHANGER includes a binary labeled `authd` that can inject a library into a running process and then hook an existing function within that process with a new function from that library.

### S0348 - Cardinal RAT

Cardinal RAT injects into a newly spawned process created from a native Windows executable.

### S0660 - Clambling

Clambling can inject into the `svchost.exe` process for execution.

### S0154 - Cobalt Strike

Cobalt Strike can inject a variety of payloads into processes dynamically chosen by the adversary.

### S0614 - CostaBricks

CostaBricks can inject a payload into the memory of a compromised host.

### S1159 - DUSTTRAP

DUSTTRAP compromises the `.text` section of a legitimate system DLL in `%windir%` to hold the contents of retrieved plug-ins.

### S0695 - Donut

Donut includes a subproject <code>DonutTest</code> to inject shellcode into a target process.

### S0024 - Dyre

Dyre has the ability to directly inject its code into the web browser process.

### S0554 - Egregor

Egregor can inject its payload into iexplore.exe process.

### S0363 - Empire

Empire contains multiple modules for injecting into processes, such as <code>Invoke-PSInject</code>.

### S0168 - Gazer

Gazer injects its communication module into an Internet accessible process through which it performs C2.

### S0561 - GuLoader

GuLoader has the ability to inject shellcode into a donor processes that is started in a suspended state. GuLoader has previously used RegAsm as a donor process.

### S0376 - HOPLIGHT

HOPLIGHT has injected into running processes.

### S0040 - HTRAN

HTRAN can inject into into running processes.

### S0398 - HyperBro

HyperBro can run shellcode it injects into a newly created process.

### S0260 - InvisiMole

InvisiMole can inject itself into another process to avoid detection including use of a technique called ListPlanting that customizes the sorting algorithm in a ListView structure.

### S0581 - IronNetInjector

IronNetInjector can use an IronPython scripts to load a .NET injector to inject a payload into its own or a remote process.

### S0044 - JHUHUGIT

JHUHUGIT performs code injection injecting its own functions to browser processes.

### S0201 - JPIN

JPIN can inject content into lsass.exe to load a module.

### S0681 - Lizar

Lizar can migrate the loader into another process.

### S0084 - Mis-Type

Mis-Type has been injected directly into a running process, including `explorer.exe`.

### S1122 - Mispadu

Mispadu's binary is injected into memory via `WriteProcessMemory`.

### S0198 - NETWIRE

NETWIRE can inject code into system processes including notepad.exe, svchost.exe, and vbc.exe.

### S0247 - NavRAT

NavRAT copies itself into a running Internet Explorer process to evade detection.

### S1100 - Ninja

Ninja has the ability to inject an agent module into a new process and arbitrary shellcode into running processes.

### S0664 - Pandora

Pandora can start and inject code into a new `svchost` process.

### S1050 - PcShare

The PcShare payload has been injected into the `logagent.exe` and `rdpclip.exe` processes.

### S0378 - PoshC2

PoshC2 contains multiple modules for injecting into processes, such as <code>Invoke-PSInject</code>.

### S0650 - QakBot

QakBot can inject itself into processes including explore.exe, Iexplore.exe, Mobsync.exe., and wermgr.exe.

### S0496 - REvil

REvil can inject itself into running processes on a compromised host.

### S0240 - ROKRAT

ROKRAT can use `VirtualAlloc`, `WriteProcessMemory`, and then `CreateRemoteThread` to execute shellcode within the address space of `Notepad.exe`.

### S0332 - Remcos

Remcos has a command to hide itself through injecting into another process.

### S0446 - Ryuk

Ryuk has injected itself into remote processes to encrypt files using a combination of <code>VirtualAlloc</code>, <code>WriteProcessMemory</code>, and <code>CreateRemoteThread</code>.

### S0692 - SILENTTRINITY

SILENTTRINITY can inject shellcode directly into Excel.exe or a specific process.

### S0533 - SLOTHFULMEDIA

SLOTHFULMEDIA can inject into running processes on a compromised host.

### S0596 - ShadowPad

ShadowPad has injected an install module into a newly created process.

### S0633 - Sliver

Sliver includes multiple methods to perform process injection to migrate the framework into other, potentially privileged processes on the victim machine.

### S0226 - Smoke Loader

Smoke Loader injects into the Internet Explorer process.

### S0380 - StoneDrill

StoneDrill has relied on injecting its payload directly into the process memory of the victim's preferred browser.

### S0436 - TSCookie

TSCookie has the ability to inject code into the svchost.exe, iexplorer.exe, explorer.exe, and default browser processes.

### S0266 - TrickBot

TrickBot has used <code>Nt*</code> Native API functions to inject code into legitimate processes such as <code>wermgr.exe</code>.

### S0670 - WarzoneRAT

WarzoneRAT has the ability to inject malicious DLLs into a specific process for privilege escalation.

### S0579 - Waterbear

Waterbear can inject decrypted shellcode into the LanmanServer service.

### S0206 - Wiarp

Wiarp creates a backdoor through which remote attackers can inject files into running processes.

### S0176 - Wingbird

Wingbird performs multiple process injections to hijack system processes and execute malicious code.

### S1065 - Woody RAT

Woody RAT can inject code into a targeted process by writing to the remote memory of an infected system and then create a remote thread.

### S0032 - gh0st RAT

gh0st RAT can inject malicious code into process created by the “Command_Create&Inject” function.

### S1059 - metaMain

metaMain can inject the loader file, Speech02.db, into a process.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0028 - 2015 Ukraine Electric Power Attack

During the 2015 Ukraine Electric Power Attack, Sandworm Team loaded BlackEnergy into svchost.exe, which then launched iexplore.exe for their C2.

### C0057 - 3CX Supply Chain Attack

During the 3CX Supply Chain Attack, AppleJeus's VEILEDSIGNAL uses process injection to inject the C2 communication module code in the first found process instance of Chrome, Firefox, or Edge web browsers. It also monitors the established named pipe and re-injects the C2 communication module if necessary.

### C0046 - ArcaneDoor

ArcaneDoor included injecting code into the AAA and Crash Dump processes on infected Cisco ASA devices.

### C0029 - Cutting Edge

During Cutting Edge, threat actors used malicious SparkGateway plugins to inject shared objects into web process memory on compromised Ivanti Secure Connect VPNs to enable deployment of backdoors.

### C0013 - Operation Sharpshooter

During Operation Sharpshooter, threat actors leveraged embedded shellcode to inject a downloader into the memory of Word.

### C0014 - Operation Wocao

During Operation Wocao, threat actors injected code into a selected process, which in turn launches a command as a child process of the original.

### C0056 - RedPenguin

During RedPenguin, UNC3886 exploited CVE-2025-21590 to enable malicious code injection into the memory of legitimate processes.
