# T1620 - Reflective Code Loading

**Tactic:** Defense Evasion
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1620

## Description

Adversaries may reflectively load code into a process in order to conceal the execution of malicious payloads. Reflective loading involves allocating then executing payloads directly within the memory of the process, vice creating a thread or process backed by a file path on disk (e.g., Shared Modules).

Reflectively loaded payloads may be compiled binaries, anonymous files (only present in RAM), or just snubs of fileless executable code (ex: position-independent shellcode). For example, the `Assembly.Load()` method executed by PowerShell may be abused to load raw code into the running process.

Reflective code injection is very similar to Process Injection except that the “injection” loads code into the processes’ own memory instead of that of a separate process. Reflective loading may evade process-based detections since the execution of the arbitrary code may be masked within a legitimate or otherwise benign process. Reflectively loading payloads directly into memory may also avoid creating files or other artifacts on disk, while also enabling malware to keep these payloads encrypted (or otherwise obfuscated) until execution.

## Detection

### Detection Analytics

**Analytic 0838**

Detect anomalous chains of memory allocation and execution inside the same process (e.g., VirtualAlloc → memcpy → VirtualProtect → CreateThread). Unlike process injection, reflective code loading does not perform cross-process memory writes — the suspicious activity occurs entirely within the process’s own PID context.

**Analytic 0839**

Monitor for in-process mmap + mprotect + execve/execveat activity where memory permissions are changed from writable to executable inside the same process without a corresponding ELF on disk.

**Analytic 0840**

Suspicious calls to dlopen(), dlsym(), or mmap with RWX flags in processes that do not typically perform dynamic module loading. Monitor anonymous memory regions executed by user processes.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1081 - BADHATCH

BADHATCH can copy a large byte array of 64-bit shellcode into process memory and execute it with a call to `CreateThread`.

### S1063 - Brute Ratel C4

Brute Ratel C4 has used reflective loading to execute malicious DLLs.

### S0154 - Cobalt Strike

Cobalt Strike's <code>execute-assembly</code> command can run a .NET executable within the memory of a sacrificial process by loading the CLR.

### S0625 - Cuba

Cuba loaded the payload into memory using PowerShell.

### S0695 - Donut

Donut can generate code modules that enable in-memory execution of VBScript, JScript, EXE, DLL, and dotNET payloads.

### S0367 - Emotet

Emotet has reflectively loaded payloads into memory.

### S0661 - FoggyWeb

FoggyWeb's loader has reflectively loaded .NET-based assembly/payloads into memory.

### S0666 - Gelsemium

Gelsemium can use custom shellcode to map embedded DLLs into memory.

### S1022 - IceApple

IceApple can use reflective code loading to load .NET assemblies into `MSExchangeOWAAppPool` on targeted Exchange servers.

### S0681 - Lizar

Lizar has used the Reflective DLL injection module from Github to inject itself into a process’s memory.

### S0447 - Lokibot

Lokibot has reflectively loaded the decoded DLL into memory.

### S1213 - Lumma Stealer

Lumma Stealer has used reflective loading techniques to load content into memory during execution.

### S1143 - LunarLoader

LunarLoader can use reflective loading to decrypt and run malicious executables in a new thread.

### S1145 - Pikabot

Pikabot reflectively loads stored, previously encrypted components of the PE file into memory of the currently executing process to avoid writing content to disk on the executing machine.

### S0013 - PlugX

PlugX has loaded its payload into memory.

### S0194 - PowerSploit

PowerSploit reflectively loads a Windows PE file into a process.

### S0692 - SILENTTRINITY

SILENTTRINITY can run a .NET executable within the memory of a sacrificial process by loading the CLR.

### S1085 - Sardonic

Sardonic has a plugin system that can load specially made DLLs into memory and execute their functions.

### S0595 - ThiefQuest

ThiefQuest uses various API functions such as <code>NSCreateObjectFileImageFromMemory</code> to load and link in-memory payloads.

### S0022 - Uroburos

Uroburos has the ability to load new modules directly into memory using its `Load Modules Mem` command.

### S0689 - WhisperGate

WhisperGate's downloader can reverse its third stage file bytes and reflectively load the file as a .NET assembly.

### S1059 - metaMain

metaMain has reflectively loaded a DLL to read, decrypt, and load an orchestrator file.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0057 - 3CX Supply Chain Attack

During the 3CX Supply Chain Attack, AppleJeus leverages the publicly available open-source project DAVESHELL to convert PE-COFF files to position-independent code to reflectively load the payload into memory.

### C0058 - SharePoint ToolShell Exploitation

During SharePoint ToolShell Exploitation, threat actors reflectively loaded payloads using `System.Reflection.Assembly.Load`.
