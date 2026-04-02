# T1106 - Native API

**Tactic:** Execution
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1106

## Description

Adversaries may interact with the native OS application programming interface (API) to execute behaviors. Native APIs provide a controlled means of calling low-level OS services within the kernel, such as those involving hardware/devices, memory, and processes. These native APIs are leveraged by the OS during system boot (when other system components are not yet initialized) as well as carrying out tasks and requests during routine operations.

Adversaries may abuse these OS API functions as a means of executing behaviors. Similar to Command and Scripting Interpreter, the native API and its hierarchy of interfaces provide mechanisms to interact with and utilize various components of a victimized system.

Native API functions (such as <code>NtCreateProcess</code>) may be directed invoked via system calls / syscalls, but these features are also often exposed to user-mode applications via interfaces and libraries. For example, functions such as the Windows API <code>CreateProcess()</code> or GNU <code>fork()</code> will allow programs and scripts to start other processes. This may allow API callers to execute a binary, run a CLI command, load modules, etc. as thousands of similar API functions exist for various system operations.

Higher level software frameworks, such as Microsoft .NET and macOS Cocoa, are also available to interact with native APIs. These frameworks typically provide language wrappers/abstractions to API functionalities and are designed for ease-of-use/portability of code.

Adversaries may use assembly to directly or in-directly invoke syscalls in an attempt to subvert defensive sensors and detection signatures such as user mode API-hooks. Adversaries may also attempt to tamper with sensors and defensive tools associated with API monitoring, such as unhooking monitored functions via Disable or Modify Tools.

## Detection

### Detection Analytics

**Analytic 1465**

Unusual or suspicious processes loading critical native API DLLs (e.g., ntdll.dll, kernel32.dll) followed by direct syscall behavior, memory manipulation, or hollowing.

**Analytic 1466**

Userland processes invoking syscall-heavy libraries (libc, glibc) followed by fork, mmap, or ptrace behavior commonly associated with code injection or memory manipulation.

**Analytic 1467**

Execution of processes that link to CoreServices or Foundation APIs followed by creation of memory regions, code execution, or abnormal library injection.


## Mitigations

### M1040 - Behavior Prevention on Endpoint

On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent Office VBA macros from calling Win32 APIs.

### M1038 - Execution Prevention

Identify and block potentially malicious software executed that may be executed through this technique by using application control tools, like Windows Defender Application Control, AppLocker, or Software Restriction Policies where appropriate.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0045 - ADVSTORESHELL

ADVSTORESHELL is capable of starting a process using CreateProcess.

### S1129 - Akira

Akira executes native Windows functions such as <code>GetFileAttributesW</code> and `GetSystemInfo`.

### S1025 - Amadey

Amadey has used a variety of Windows API calls, including `GetComputerNameA`, `GetUserNameA`, and `CreateProcessA`.

### S0622 - AppleSeed

AppleSeed has the ability to use multiple dynamically resolved API calls.

### S0456 - Aria-body

Aria-body has the ability to launch files using <code>ShellExecute</code>.

### S1087 - AsyncRAT

AsyncRAT has the ability to use OS APIs including `CheckRemoteDebuggerPresent`.

### S0438 - Attor

Attor's dispatcher has used CreateProcessW API for execution.

### S0640 - Avaddon

Avaddon has used the Windows Crypto API to generate an AES key.

### S1053 - AvosLocker

AvosLocker has used a variety of Windows API calls, including `NtCurrentPeb` and `GetLogicalDrives`.

### S1081 - BADHATCH

BADHATCH can utilize Native API functions such as, `ToolHelp32` and `Rt1AdjustPrivilege` to enable `SeDebugPrivilege` on a compromised machine.

### S0128 - BADNEWS

BADNEWS has a command to download an .exe and execute it via CreateProcess API. It can also run with ShellExecute.

### S0470 - BBK

BBK has the ability to use the <code>CreatePipe</code> API to add a sub-process for execution via cmd.

### S1226 - BOOKWORM

BOOKWORM has used various Windows API calls during execution and defense evasion. BOOKWORM has created a buffer on the heap using `HeapCreate` and `HeapAlloc` which allows for copying of shell code and then execution on the heap is initiated through callback function of legitimate API functions such as `EnumChildWindows` or `EnumSystemLanguageGroupsA`.

### S0638 - Babuk

Babuk can use multiple Windows API calls for actions on compromised hosts including discovery and execution.

### S0475 - BackConfig

BackConfig can leverage API functions such as <code>ShellExecuteA</code> and <code>HttpOpenRequestA</code> in the process of downloading and executing files.

### S0606 - Bad Rabbit

Bad Rabbit has used various Windows API calls.

### S0234 - Bandook

Bandook has used the ShellExecuteW() function call.

### S0239 - Bankshot

Bankshot creates processes using the Windows API calls: CreateProcessA() and CreateProcessAsUserA().

### S0534 - Bazar

Bazar can use various APIs to allocate memory and facilitate code execution/injection.

### S0574 - BendyBear

BendyBear can load and execute modules and Windows Application Programming (API) calls using standard shellcode API hashing.

### S0268 - Bisonal

Bisonal has used the Windows API to communicate with the Service Control Manager to execute a thread.

### S0570 - BitPaymer

BitPaymer has used dynamic API resolution to avoid identifiable strings within the binary, including <code>RegEnumKeyW</code>.

### S1070 - Black Basta

Black Basta has the ability to use native APIs for numerous functions including discovery and defense evasion.

### S1180 - BlackByte Ransomware

BlackByte Ransomware uses the `SetThreadExecutionState` API to prevent the victim system from entering sleep.

### S0521 - BloodHound

BloodHound can use .NET API calls in the SharpHound ingestor component to pull Active Directory data.

### S0651 - BoxCaon

BoxCaon has used Windows API calls to obtain information about the compromised host.

### S1063 - Brute Ratel C4

Brute Ratel C4 can call multiple Windows APIs for execution, to share memory, and defense evasion.

### S1039 - Bumblebee

Bumblebee can use multiple Native APIs.

### S1237 - CANONSTAGER

CANONSTAGER has leveraged Native API calls to execute code within the victim’s system including `GetCurrentDirectoryW`, `RegisterClassW` and `CreateWindowExW`. CANONSTAGER also created a new overlapped window that initiates callback functions to a windows procedure that processes Windows messages until a designated message type of 0x0018 WM_SHOWWINDOW is observed which then initiates the deployment of a subsequent malicious payload.

### S1149 - CHIMNEYSWEEP

CHIMNEYSWEEP can use Windows APIs including `LoadLibrary` and `GetProcAddress`.

### S1236 - CLAIMLOADER

CLAIMLOADER has used various Windows API calls during execution, when establishing persistence and defense evasion.  CLAIMLOADER has also leveraged the legitimate API functions to run its shellcode through the callback function, including `GetDC()` and `EnumFontsW()`.  CLAIMLOADER established persistence by utilizing the API `SHSetValue()`. CLAIMLOADER has utilized APIs with callback functions such as `EnumpropsExW`, `EnumSystemLanguageGroupsA`, and `EnumCalendarInfoExW`.

### S0693 - CaddyWiper

CaddyWiper has the ability to dynamically resolve and use APIs, including `SeTakeOwnershipPrivilege`.

### S0484 - Carberp

Carberp has used the NtQueryDirectoryFile and ZwQueryDirectoryFile functions to hide files and directories.

### S0631 - Chaes

Chaes used the <code>CreateFileW()</code> API function with read permissions to access downloaded payloads.

### S0667 - Chrommme

Chrommme can use Windows API including `WinExec` for execution.

### S0611 - Clop

Clop has used built-in API functions such as WNetOpenEnumW(), WNetEnumResourceW(), WNetCloseEnum(), GetProcAddress(), and VirtualAlloc().

### S0154 - Cobalt Strike

Cobalt Strike's Beacon payload is capable of running shell commands without <code>cmd.exe</code> and PowerShell commands without <code>powershell.exe</code>

### S0126 - ComRAT

ComRAT can load a PE file from memory or the file system and execute it with <code>CreateProcessW</code>.

### S0575 - Conti

Conti has used API calls during execution.

### S0614 - CostaBricks

CostaBricks has used a number of API calls, including `VirtualAlloc`, `VirtualFree`, `LoadLibraryA`, `GetProcAddress`, and `ExitProcess`.

### S0625 - Cuba

Cuba has used several built-in API functions for discovery like GetIpNetTable and NetShareEnum.

### S0687 - Cyclops Blink

Cyclops Blink can use various Linux API functions including those for execution and discovery.

### S1033 - DCSrv

DCSrv has used various Windows API functions, including `DeviceIoControl`, as part of its encryption process.

### S1052 - DEADEYE

DEADEYE can execute the `GetComputerNameA` and `GetComputerNameExA` WinAPI functions.

### S0694 - DRATzarus

DRATzarus can use various API calls to see if it is running in a sandbox.

### S1111 - DarkGate

DarkGate uses the native Windows API <code>CallWindowProc()</code> to decode and launch encoded shellcode payloads during execution. DarkGate can call kernel mode functions directly to hide the use of process hollowing methods during execution. DarkGate has also used the `CreateToolhelp32Snapshot`, `GetFileAttributesA` and `CreateProcessA` functions to obtain a list of running processes, to check for security products and to execute its malware.

### S1066 - DarkTortilla

DarkTortilla can use a variety of API calls for persistence and defense evasion.

### S0354 - Denis

Denis used the <code>IsDebuggerPresent</code>, <code>OutputDebugString</code>, and <code>SetLastError</code> APIs to avoid debugging. Denis used <code>GetProcAddress</code> and <code>LoadLibrary</code> to dynamically resolve APIs. Denis also used the <code>Wow64SetThreadContext</code> API as part of a process hollowing process.

### S0659 - Diavol

Diavol has used several API calls like `GetLogicalDriveStrings`, `SleepEx`, `SystemParametersInfoAPI`, `CryptEncrypt`, and others to execute parts of its attack.

### S0695 - Donut

Donut code modules use various API functions to load and inject code.

### S0384 - Dridex

Dridex has used the <code>OutputDebugStringW</code> function to avoid malware analysis as part of its anti-debugging technique.

### S0554 - Egregor

Egregor has used the Windows API to make detection more difficult.

### S1247 - Embargo

Embargo has leveraged Windows Native API functions to execute its operations.

### S0367 - Emotet

Emotet has used `CreateProcess` to create a new process to run its executable and `WNetEnumResourceW` to enumerate non-hidden shares.

### S0363 - Empire

Empire contains a variety of enumeration modules that have an option to use API calls to carry out tasks.

### S0396 - EvilBunny

EvilBunny has used various API calls as part of its checks to see if the malware is running in a sandbox.

### S1179 - Exbyte

Exbyte calls `ShellExecuteW` with the `IpOperation` parameter `RunAs` to launch `explorer.exe` with elevated privileges.

### S0569 - Explosive

Explosive has a function to call the OpenClipboard wrapper.

### S0512 - FatDuke

FatDuke can call <code>ShellExecuteW</code> to open the default browser on the URL localhost.

### S0696 - Flagpro

Flagpro can use Native API to enable obfuscation including `GetLastError` and `GetTickCount`.

### S0661 - FoggyWeb

FoggyWeb's loader can use API functions to load the FoggyWeb backdoor into the same Application Domain within which the legitimate AD FS managed code is executed.

### S1044 - FunnyDream

FunnyDream can use Native API for defense evasion, discovery, and collection.

### S0666 - Gelsemium

Gelsemium has the ability to use various Windows API functions to perform tasks.

### S0493 - GoldenSpy

GoldenSpy can execute remote commands in the Windows command shell using the <code>WinExec()</code> API.

### S0477 - Goopy

Goopy has the ability to  enumerate the infected system's user name via <code>GetUserNameW</code>.

### S0531 - Grandoreiro

Grandoreiro can execute through the <code>WinExec</code> API.

### S0632 - GrimAgent

GrimAgent can use Native API including <code>GetProcAddress</code> and <code>ShellExecuteW</code>.

### S0561 - GuLoader

GuLoader can use a number of different APIs for discovery and execution.

### S0391 - HAWKBALL

HAWKBALL has leveraged several Windows API calls to create processes, gather disk information, and detect debugger activity.

### S0499 - Hancitor

Hancitor has used <code>CallWindowProc</code> and <code>EnumResourceTypesA</code> to interpret and execute shellcode.

### S1229 - Havoc

Havoc can use `NtAllocateVirtualMemory` and `NtCreateThreadEx` to aid process injection.

### S0697 - HermeticWiper

HermeticWiper can call multiple Windows API functions used for privilege escalation, service execution, and to overwrite random bites of data.

### S0698 - HermeticWizard

HermeticWizard can connect to remote shares using `WNetAddConnection2W`.

### S0431 - HotCroissant

HotCroissant can perform dynamic DLL importing and API lookups using <code>LoadLibrary</code> and <code>GetProcAddress</code> on obfuscated strings.

### S0398 - HyperBro

HyperBro has the ability to run an application (<code>CreateProcessW</code>) or script/file (<code>ShellExecuteW</code>) via API.

### S0537 - HyperStack

HyperStack can use Windows API's <code>ConnectNamedPipe</code> and <code>WNetAddConnection2</code> to detect incoming connections and connect to remote shares.

### S1152 - IMAPLoader

IMAPLoader imports native Windows APIs such as `GetConsoleWindow` and `ShowWindow`.

### S1139 - INC Ransomware

INC Ransomware can use the API `DeviceIoControl` to resize the allocated space for and cause the deletion of volume shadow copy snapshots.

### S0483 - IcedID

IcedID has called <code>ZwWriteVirtualMemory</code>, <code>ZwProtectVirtualMemory</code>, <code>ZwQueueApcThread</code>, and <code>NtResumeThread</code> to inject itself into a remote process.

### S0434 - Imminent Monitor

Imminent Monitor has leveraged CreateProcessW() call to execute the debugger.

### S0259 - InnaputRAT

InnaputRAT uses the API call ShellExecuteW for execution.

### S0260 - InvisiMole

InvisiMole can use winapiexec tool for indirect execution of  <code>ShellExecuteW</code> and <code>CreateProcessA</code>.

### S0669 - KOCTOPUS

KOCTOPUS can use the `LoadResource` and `CreateProcessW` APIs for execution.

### S0356 - KONNI

KONNI has hardcoded API calls within its functions to use on the victim's machine.

### S1190 - Kapeka

Kapeka utilizes WinAPI calls to gather victim system information.

### S1020 - Kevin

Kevin can use the `ShowWindow` API to avoid detection.

### S0607 - KillDisk

KillDisk has called the Windows API to retrieve the hard disk handle and shut down the machine.

### S1160 - Latrodectus

Latrodectus has used multiple Windows API post exploitation including `GetAdaptersInfo`, `CreateToolhelp32Snapshot`, and `CreateProcessW`.

### S0395 - LightNeuron

LightNeuron is capable of starting a process using CreateProcess.

### S0680 - LitePower

LitePower can use various API calls.

### S0681 - Lizar

Lizar has used various Windows API functions on a victim's machine.

### S1202 - LockBit 3.0

LockBit 3.0 has the ability to directly call native Windows API items during execution.

### S0447 - Lokibot

Lokibot has used LoadLibrary(), GetProcAddress() and CreateRemoteThread() API functions to execute its shellcode.

### S1016 - MacMa

MacMa has used macOS API functions to perform tasks.

### S1060 - Mafalda

Mafalda can use a variety of API calls.

### S1169 - Mango

Mango has the ability to use Native APIs.

### S0652 - MarkiRAT

MarkiRAT can run the ShellExecuteW API via the Windows Command Shell.

### S0449 - Maze

Maze has used several Windows API functions throughout the encryption process including IsDebuggerPresent, TerminateProcess, Process32FirstW, among others.

### S1244 - Medusa Ransomware

Medusa Ransomware has leveraged Windows Native API functions to execute payloads.

### S0576 - MegaCortex

After escalating privileges, MegaCortex calls <code>TerminateProcess()</code>, <code>CreateRemoteThread</code>, and other Win32 APIs.

### S0455 - Metamorfo

Metamorfo has used native WINAPI calls.

### S0688 - Meteor

Meteor can use `WinAPI` to remove a victim machine from an Active Directory domain.

### S1015 - Milan

Milan can use the API `DnsQuery_A` for DNS resolution.

### S0084 - Mis-Type

Mis-Type has used Windows API calls, including `NetUserAdd` and `NetUserDel`.

### S0083 - Misdat

Misdat has used Windows APIs, including `ExitWindowsEx` and `GetKeyboardType`.

### S1122 - Mispadu

Mispadu has used a variety of Windows API calls, including ShellExecute and WriteProcessMemory.

### S0256 - Mosquito

Mosquito leverages the CreateProcess() and LoadLibrary() calls to execute files with the .dll and .exe extensions.

### S0198 - NETWIRE

NETWIRE can use Native API including <code>CreateProcess</code> <code>GetProcessById</code>, and <code>WriteProcessMemory</code>.

### S0630 - Nebulae

Nebulae has the ability to use <code>CreateProcess</code> to execute a process.

### S0457 - Netwalker

Netwalker can use Windows API functions to inject the ransomware DLL.

### S1090 - NightClub

NightClub can use multiple native APIs including `GetKeyState`, `GetForegroundWindow`, `GetWindowThreadProcessId`, and `GetKeyboardLayout`.

### S1100 - Ninja

The Ninja loader can call Windows APIs for discovery, process injection, and payload decryption.

### S1170 - ODAgent

ODAgent can pass commands using native APIs.

### S1172 - OilBooster

OilBooster has used the `ShowWindow` and `CreateProcessW` APIs.

### S1233 - PAKLOG

PAKLOG has used Windows API `SetWindowsHookExW` with `idHook` set to `WH_KEYBOARD_LL` and a custom hook procedure to support its keylogging functions.

### S0435 - PLEAD

PLEAD can use `ShellExecute` to execute applications.

### S1228 - PUBLOAD

PUBLOAD has used various Windows API calls during execution, when establishing persistence and defense evasion. PUBLOAD stager leveraged Windows API functions with callback including `GrayStringW`, `EnumDateFormatsA`, and `LineDDA` to bypass anti-virus monitoring. PUBLOAD has also utilized other native windows API functions with callback functions such as `EnumChildWindows` and `EnumSystemLanguageGroupsA`.

### S1050 - PcShare

PcShare has used a variety of Windows API functions.

### S1145 - Pikabot

Pikabot uses native Windows APIs to determine if the process is being debugged and analyzed, such as `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, `ProcessDebugPort`, and `ProcessDebugFlags`. Other Pikabot variants populate a global list of Windows API addresses from the `NTDLL` and `KERNEL32` libraries, and references these items instead of calling the API items to obfuscate execution.

### S0517 - Pillowmint

Pillowmint has used multiple native Windows APIs to execute and conduct process injections.

### S0501 - PipeMon

PipeMon's first stage has been executed by a call to <code>CreateProcess</code> with the decryption password in an argument. PipeMon has used a call to <code>LoadLibrary</code> to load its installer.

### S0013 - PlugX

PlugX can use the Windows API functions `GetProcAddress`, `LoadLibrary`, and `CreateProcess` to execute another process.

### S0518 - PolyglotDuke

PolyglotDuke can use <code>LoadLibraryW</code> and <code>CreateProcess</code> to load and execute code.

### S0453 - Pony

Pony has used several Windows functions for various purposes.

### S1058 - Prestige

Prestige has used the `Wow64DisableWow64FsRedirection()` and `Wow64RevertWow64FsRedirection()` functions to disable and restore file system redirection.

### S0147 - Pteranodon

Pteranodon has used various API calls.

### S1076 - QUIETCANARY

QUIETCANARY can call `System.Net.HttpWebRequest` to identify the default proxy configured on the victim computer.

### S0650 - QakBot

QakBot can use <code>GetProcAddress</code> to help delete malicious strings from memory.

### S1242 - Qilin

Qilin can attempt to log on to the local computer via `LogonUserW` and use `GetLogicalDrives()` and `EnumResourceW()` for discovery.

### S0662 - RCSession

RCSession can use WinSock API for communication including <code>WSASend</code> and <code>WSARecv</code>.

### S0416 - RDFSNIFFER

RDFSNIFFER has used several Win32 API functions to interact with the victim machine.

### S0496 - REvil

REvil can use Native API for execution and to retrieve active services.

### S0240 - ROKRAT

ROKRAT can use a variety of API calls to execute shellcode.

### S0148 - RTM

RTM can use the <code>FindNextUrlCacheEntryA</code> and <code>FindFirstUrlCacheEntryA</code> functions to search for specific strings within browser history.

### S0629 - RainyDay

The file collection tool used by RainyDay can utilize native API including <code>ReadDirectoryChangeW</code> for folder monitoring.

### S0458 - Ramsay

Ramsay can use Windows API functions such as <code>WriteFile</code>, <code>CloseHandle</code>, and <code>GetCurrentHwProfile</code> during its collection and file storage operations. Ramsay can execute its embedded components via <code>CreateProcessA</code> and <code>ShellExecute</code>.

### S0448 - Rising Sun

Rising Sun used dynamic API resolutions to various Windows APIs by leveraging `LoadLibrary()` and `GetProcAddress()`.

### S1078 - RotaJakiro

When executing with non-root permissions, RotaJakiro uses the the `shmget` API to create shared memory between other known RotaJakiro processes. RotaJakiro also uses the `execvp` API to help its dead process "resurrect".

### S1073 - Royal

Royal can use multiple APIs for discovery, communication, and execution.

### S0446 - Ryuk

Ryuk has used multiple native APIs including <code>ShellExecuteW</code> to run executables,<code>GetWindowsDirectoryW</code> to create folders, and <code>VirtualAlloc</code>, <code>WriteProcessMemory</code>, and <code>CreateRemoteThread</code> for process injection.

### S0085 - S-Type

S-Type has used Windows APIs, including `GetKeyboardType`, `NetUserAdd`, and `NetUserDel`.

### S0692 - SILENTTRINITY

SILENTTRINITY has the ability to leverage API including `GetProcAddress` and `LoadLibrary`.

### S0562 - SUNSPOT

SUNSPOT used Windows API functions such as <code>MoveFileEx</code> and <code>NtQueryInformationProcess</code> as part of the SUNBURST injection process.

### S1064 - SVCReady

SVCReady can use Windows API calls to gather information from an infected host.

### S1210 - Sagerunex

Sagerunex calls the `WaitForSingleObject` API function as part of time-check logic.

### S1018 - Saint Bot

Saint Bot has used different API calls, including `GetProcAddress`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateProcessA`, and `SetThreadContext`.

### S1099 - Samurai

Samurai has the ability to call Windows APIs.

### S1085 - Sardonic

Sardonic has the ability to call Win32 API functions to determine if `powershell.exe` is running.

### S1089 - SharpDisco

SharpDisco can leverage Native APIs through plugins including `GetLogicalDrives`.

### S0444 - ShimRat

ShimRat has used Windows API functions to install the service and shim.

### S0445 - ShimRatReporter

ShimRatReporter used several Windows API functions to gather information from the infected system.

### S0610 - SideTwist

SideTwist can use <code>GetUserNameW</code>, <code>GetComputerNameW</code>, and <code>GetComputerNameExW</code> to gather information.

### S0623 - Siloscape

Siloscape makes various native API calls.

### S0627 - SodaMaster

SodaMaster can use <code>RegOpenKeyW</code> to access the Registry.

### S0615 - SombRAT

SombRAT has the ability to respawn itself using <code>ShellExecuteW</code> and <code>CreateProcessW</code>.

### S1234 - SplatCloak

SplatCloak has utilized Native Windows API calls dynamically through `ZwQuerySystemInformation`.

### S1232 - SplatDropper

SplatDropper has utilized hashed Native Windows API calls.

### S1227 - StarProxy

StarProxy has used native windows API calls such as `GetLocalTime()` to retrieve system data.

### S1200 - StealBit

StealBit can use native APIs including `LoadLibraryExA` for execution and `NtSetInformationProcess` for defense evasion purposes.

### S1034 - StrifeWater

StrifeWater can use a variety of APIs for execution.

### S0603 - Stuxnet

Stuxnet uses the SetSecurityDescriptorDacl API to reduce object integrity levels.

### S0242 - SynAck

SynAck parses the export tables of system DLLs to locate and call various Windows API functions.

### S0663 - SysUpdate

SysUpdate can call the `GetNetworkParams` API as part of its C2 establishment process.

### S1239 - TONESHELL

TONESHELL has utilized Native Windows API functions such as `WriteProcessMemory` and `CreateRemoteThreadEx`. TONESHELL has also utilized Windows API functions for creating seed values including `CoCreateGuid` and `GetTickCount`. TONESHELL has leveraged the legitimate API function `EnumSystemLocalesA` to run its shellcode through the callback function.

### S0011 - Taidoor

Taidoor has the ability to use native APIs for execution including <code>GetProcessHeap</code>, <code>GetProcAddress</code>, and <code>LoadLibrary</code>.

### S0595 - ThiefQuest

ThiefQuest uses various API to perform behaviors such as executing payloads and performing local enumeration.

### S0668 - TinyTurla

TinyTurla has used `WinHTTP`, `CreateProcess`, and other APIs for C2 communications and other functions.

### S0678 - Torisma

Torisma has used various Windows API calls.

### S0266 - TrickBot

TrickBot uses the Windows API call, CreateProcessW(), to manage execution flow. TrickBot has also used <code>Nt*</code> API functions to perform Process Injection.

### S0022 - Uroburos

Uroburos can use native Windows APIs including `GetHostByName`.

### S0386 - Ursnif

Ursnif has used <code>CreateProcessW</code> to create child processes.

### S0180 - Volgmer

Volgmer executes payloads using the Windows API call CreateProcessW().

### S0670 - WarzoneRAT

WarzoneRAT can use a variety of API calls on a compromised host.

### S0612 - WastedLocker

WastedLocker's custom crypter, CryptOne, leveraged the VirtualAlloc() API function to help execute the payload.

### S0579 - Waterbear

Waterbear can leverage API functions for execution.

### S0689 - WhisperGate

WhisperGate has used the `ExitWindowsEx` to flush file buffers to disk and stop running processes and other API calls.

### S0466 - WindTail

WindTail can invoke Apple APIs <code>contentsOfDirectoryAtPath</code>, <code>pathExtension</code>, and (string) <code>compare</code>.

### S0141 - Winnti for Windows

Winnti for Windows can use Native API to create a new process and to start services.

### S1065 - Woody RAT

Woody RAT can use multiple native APIs, including `WriteProcessMemory`, `CreateProcess`, and `CreateRemoteThread` for process injection.

### S0161 - XAgentOSX

XAgentOSX contains the execFile function to execute a specified file on the system using the NSTask:launch method.

### S1207 - XLoader

XLoader uses the native Windows API for functionality, including defense evasion.

### S1151 - ZeroCleare

ZeroCleare can call the `GetSystemDirectoryW` API to locate the system directory.

### S0412 - ZxShell

ZxShell can leverage native API including <code>RegisterServiceCtrlHandler </code> to register a service.RegisterServiceCtrlHandler

### S1013 - ZxxZ

ZxxZ has used API functions such as `Process32First`, `Process32Next`, and `ShellExecuteA`.

### S0471 - build_downer

build_downer has the ability to use the <code>WinExec</code> API to execute malware on a compromised host.

### S0032 - gh0st RAT

gh0st RAT has used the `InterlockedExchange`, `SeShutdownPrivilege`, and `ExitWindowsEx` Windows API functions.

### S1059 - metaMain

metaMain can execute an operator-provided Windows command by leveraging functions such as `WinExec`, `WriteFile`, and `ReadFile`.

### S0385 - njRAT

njRAT has used the ShellExecute() function within a script.

### S0653 - xCaon

xCaon has leveraged native OS function calls to retrieve  victim's network adapter's  information using GetAdapterInfo() API.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0022 - Operation Dream Job

During Operation Dream Job, Lazarus Group used Windows API `ObtainUserAgentString` to obtain the victim's User-Agent and used the value to connect to their C2 server.

### C0006 - Operation Honeybee

During Operation Honeybee, the threat actors deployed malware that used API calls, including `CreateProcessAsUser`.

### C0013 - Operation Sharpshooter

During Operation Sharpshooter, the first stage downloader resolved various Windows libraries and APIs, including `LoadLibraryA()`, `GetProcAddress()`, and `CreateProcessA()`.

### C0014 - Operation Wocao

During Operation Wocao, threat actors used the `CreateProcessA` and `ShellExecute` API functions to launch commands after being injected into a selected process.
