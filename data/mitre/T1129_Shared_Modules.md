# T1129 - Shared Modules

**Tactic:** Execution
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1129

## Description

Adversaries may execute malicious payloads via loading shared modules. Shared modules are executable files that are loaded into processes to provide access to reusable code, such as specific custom functions or invoking OS API functions (i.e., Native API).

Adversaries may use this functionality as a way to execute arbitrary payloads on a victim system. For example, adversaries can modularize functionality of their malware into shared objects that perform various functions such as managing C2 network communications or execution of specific actions on objective.

The Linux & macOS module loader can load and execute shared objects from arbitrary local paths. This functionality resides in `dlfcn.h` in functions such as `dlopen` and `dlsym`. Although macOS can execute `.so` files, common practice uses `.dylib` files.

The Windows module loader can be instructed to load DLLs from arbitrary local paths and arbitrary Universal Naming Convention (UNC) network paths. This functionality resides in `NTDLL.dll` and is part of the Windows Native API which is called from functions like `LoadLibrary` at run time.

## Detection

### Detection Analytics

**Analytic 0052**

A process (often LOLBin or user-launched program) loads a DLL from a user-writable/UNC/Temp path or unsigned/invalid signer. Within a short window the DLL is (a) newly written to disk, (b) spawned as follow-on execution (rundll32/regsvr32), or (c) establishes outbound C2.

**Analytic 0053**

A process loads a shared object (.so) via dlopen/LD_PRELOAD/open from non-standard or temporary locations (e.g., /tmp, /dev/shm), especially shortly after that .so is written or fetched, or linked via manipulated environment variables (LD_PRELOAD/LD_LIBRARY_PATH).

**Analytic 0054**

A process loads a non-system .dylib/.so via dyld (dlopen/dlsym) from user-writable locations (~/Library, /tmp) or after the library was recently created/downloaded, often followed by network egress or persistence.


## Mitigations

### M1038 - Execution Prevention

Identify and block potentially malicious software executed through this technique by using application control tools capable of preventing unknown modules from being loaded.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0373 - Astaroth

Astaroth uses the LoadLibraryExW() function to load additional modules.

### S0438 - Attor

Attor's dispatcher can execute additional plugins by loading the respective DLLs.

### S0520 - BLINDINGCAN

BLINDINGCAN has loaded and executed DLLs in memory during runtime on a victim machine.

### S0415 - BOOSTWRITE

BOOSTWRITE has used the DWriteCreateFactory() function to load additional modules.

### S1039 - Bumblebee

Bumblebee can use `LoadLibrary` to attempt to execute GdiPlus.dll.

### S0673 - DarkWatchman

DarkWatchman can load DLLs.

### S0567 - Dtrack

Dtrack contains a function that calls <code>LoadLibrary</code> and <code>GetProcAddress</code>.

### S0377 - Ebury

Ebury is executed through hooking the keyutils.so file used by legitimate versions of `OpenSSH` and `libcurl`.

### S0661 - FoggyWeb

FoggyWeb's loader can call the <code>load()</code> function to load the FoggyWeb dll into an Application Domain on a compromised AD FS server.

### S0203 - Hydraq

Hydraq creates a backdoor through which remote attackers can load and call DLL functions.

### S0607 - KillDisk

KillDisk loads and executes functions from a DLL.

### S1185 - LightSpy

LightSpy's main executable and module `.dylib` binaries are loaded using a combination of `dlopen()` to load the library, `_objc_getClass()` to retrieve the class definition, and `_objec_msgSend()` to invoke/execute the specified method in the loaded class.

### S0455 - Metamorfo

Metamorfo had used AutoIt to load and execute the DLL payload.

### S0352 - OSX_OCEANLOTUS.D

For network communications, OSX_OCEANLOTUS.D loads a dynamic library (`.dylib` file) using `dlopen()` and obtains a function pointer to execute within that shared library using `dlsym()`.

### S0196 - PUNCHBUGGY

PUNCHBUGGY can load a DLL using the LoadLibrary API.

### S0501 - PipeMon

PipeMon has used call to <code>LoadLibrary</code> to load its installer. PipeMon loads its modules using reflective loading or custom shellcode.

### S1078 - RotaJakiro

RotaJakiro uses dynamically linked shared libraries (`.so` files) to execute additional functionality using `dlopen()` and `dlsym()`.

### S0603 - Stuxnet

Stuxnet calls LoadLibrary then executes exports from a DLL.

### S0467 - TajMahal

TajMahal has the ability to inject the <code>LoadLibrary</code> call template DLL into running processes.

### S1154 - VersaMem

VersaMem relied on the Java Instrumentation API and Javassist to dynamically modify Java code existing in memory.

### S0032 - gh0st RAT

gh0st RAT can load DLLs into memory.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
