# T1622 - Debugger Evasion

**Tactic:** Defense Evasion, Discovery
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1622

## Description

Adversaries may employ various means to detect and avoid debuggers. Debuggers are typically used by defenders to trace and/or analyze the execution of potential malware payloads.

Debugger evasion may include changing behaviors based on the results of the checks for the presence of artifacts indicative of a debugged environment. Similar to Virtualization/Sandbox Evasion, if the adversary detects a debugger, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for debugger artifacts before dropping secondary or additional payloads.

Specific checks will vary based on the target and/or adversary. On Windows, this may involve Native API function calls such as <code>IsDebuggerPresent()</code> and <code> NtQueryInformationProcess()</code>, or manually checking the <code>BeingDebugged</code> flag of the Process Environment Block (PEB). On Linux, this may involve querying `/proc/self/status` for the `TracerPID` field, which indicates whether or not the process is being traced by dynamic analysis tools. Other checks for debugging artifacts may also seek to enumerate hardware breakpoints, interrupt assembly opcodes, time checks, or measurements if exceptions are raised in the current process (assuming a present debugger would “swallow” or handle the potential error).

Malware may also leverage Structured Exception Handling (SEH) to detect debuggers by throwing an exception and detecting whether the process is suspended. SEH handles both hardware and software expectations, providing control over the exceptions including support for debugging. If a debugger is present, the program’s control will be transferred to the debugger, and the execution of the code will be suspended. If the debugger is not present, control will be transferred to the SEH handler, which will automatically handle the exception and allow the program’s execution to continue.

Adversaries may use the information learned from these debugger checks during automated discovery to shape follow-on behaviors. Debuggers can also be evaded by detaching the process or flooding debug logs with meaningless data via messages produced by looping Native API function calls such as <code>OutputDebugStringW()</code>.

## Detection

### Detection Analytics

**Analytic 1045**

Monitor for suspicious use of Windows API calls such as IsDebuggerPresent() and NtQueryInformationProcess(), or processes manually checking the BeingDebugged flag in the Process Environment Block (PEB). Detect sequences of OutputDebugStringW() calls in short intervals that may indicate debugger flooding attempts.

**Analytic 1046**

Monitor access to /proc/self/status where TracerPID field is queried, as this is a common technique for debugger detection. Detect processes that attempt to trigger exceptions intentionally and monitor whether exception handling indicates presence of a debugger.

**Analytic 1047**

Detect suspicious calls to sysctl or ptrace API used to determine if a process is being debugged. Monitor for processes that flood OutputDebugString equivalents or generate abnormal exceptions to evade analysis.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1087 - AsyncRAT

AsyncRAT can use the `CheckRemoteDebuggerPresent` function to detect the presence of a debugger.

### S1070 - Black Basta

The Black Basta dropper can check system flags, CPU registers, CPU instructions, process timing, system libraries, and APIs to determine if a debugger is present.

### S1039 - Bumblebee

Bumblebee can search for tools used in static analysis.

### S0694 - DRATzarus

DRATzarus can use `IsDebuggerPresent` to detect whether a debugger is present on a victim.

### S1111 - DarkGate

DarkGate checks the <code>BeingDebugged</code> flag in the PEB structure during execution to identify if the malware is being debugged.

### S1066 - DarkTortilla

DarkTortilla can detect debuggers by using functions such as `DebuggerIsAttached` and `DebuggerIsLogging`. DarkTortilla can also detect profilers by verifying the `COR_ENABLE_PROFILING` environment variable is present and active.

### S1160 - Latrodectus

Latrodectus has the ability to check for the presence of debuggers.

### S1202 - LockBit 3.0

LockBit 3.0 can check heap memory parameters for indications of a debugger and stop the flow of events to the attached debugger in order to hinder dynamic analysis.

### S1213 - Lumma Stealer

Lumma Stealer has checked for debugger strings by invoking `GetForegroundWindow` and looks for strings containing “x32dbg”, “x64dbg”, “windbg”, “ollydbg”, “dnspy”, “immunity debugger”, “hyperdbg”, “debug”, “debugger”, “cheat engine”, “cheatengine” and “ida”.

### S1060 - Mafalda

Mafalda can search for debugging tools on a compromised host.

### S1228 - PUBLOAD

PUBLOAD has embedded debug strings with messages to distract analysts.  PUBLOAD has leveraged `OutputDebugStringW` and `OutputDebugStringA` functions.

### S1145 - Pikabot

Pikabot features several methods to evade debugging by analysts, including checks for active debuggers, the use of breakpoints during execution, and checking various system information items such as system memory and the number of processors.

### S0013 - PlugX

PlugX has made calls to Windows API `CheckRemoteDebuggerPresent` and exits if it detects a debugger.

### S0240 - ROKRAT

ROKRAT can check for debugging tools.

### S1130 - Raspberry Robin

Raspberry Robin leverages anti-debugging mechanisms through the use of <code>ThreadHideFromDebugger</code>.

### S1018 - Saint Bot

Saint Bot has used `is_debugger_present` as part of its environmental checks.

### S1200 - StealBit

StealBit can detect it is being run in the context of a debugger.

### S1183 - StrelaStealer

StrelaStealer variants include functionality to identify and evade debuggers.

### S1239 - TONESHELL

TONESHELL has leveraged custom exception handlers to hide code flow and stop execution of a debugger.

### S0595 - ThiefQuest

ThiefQuest uses a function named <code>is_debugging</code> to perform anti-debugging logic. The function invokes <code>sysctl</code> checking the returned value of <code>P_TRACED</code>. ThiefQuest also calls <code>ptrace</code> with the <code>PTRACE_DENY_ATTACH</code> flag to prevent debugging.

### S1207 - XLoader

XLoader uses anti-debugging mechanisms such as calling `NtQueryInformationProcess` with `InfoClass=7`, referencing `ProcessDebugPort`, to determine if it is being analyzed.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0022 - Operation Dream Job

During Operation Dream Job, Lazarus Group used tools that used the `IsDebuggerPresent` call to detect debuggers.
