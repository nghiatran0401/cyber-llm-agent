# T1559 - Inter-Process Communication

**Tactic:** Execution
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1559

## Description

Adversaries may abuse inter-process communication (IPC) mechanisms for local code or command execution. IPC is typically used by processes to share data, communicate with each other, or synchronize execution. IPC is also commonly used to avoid situations such as deadlocks, which occurs when processes are stuck in a cyclic waiting pattern. 

Adversaries may abuse IPC to execute arbitrary code or commands. IPC mechanisms may differ depending on OS, but typically exists in a form accessible through programming languages/libraries or native interfaces such as Windows Dynamic Data Exchange or Component Object Model. Linux environments support several different IPC mechanisms, two of which being sockets and pipes. Higher level execution mediums, such as those of Command and Scripting Interpreters, may also leverage underlying IPC mechanisms. Adversaries may also use Remote Services such as Distributed Component Object Model to facilitate remote IPC execution.

## Detection

### Detection Analytics

**Analytic 1357**

Detects anomalous use of COM, DDE, or named pipes for execution. Correlates creation or access of IPC mechanisms (e.g., named pipes, COM objects) with unusual parent-child process relationships or code injection patterns (e.g., Office spawning cmd.exe via DDE).

**Analytic 1358**

Detects abuse of UNIX domain sockets, pipes, or message queues for unauthorized code execution. Correlates unexpected socket creation with suspicious binaries, abnormal shell pipelines, or injected processes establishing IPC channels.

**Analytic 1359**

Detects anomalous use of Mach ports, Apple Events, or XPC services for inter-process execution or code injection. Focuses on unexpected processes attempting to send privileged Apple Events (e.g., automation scripts injecting into security-sensitive apps).


## Mitigations

### M1013 - Application Developer Guidance

Enable the Hardened Runtime capability when developing applications. Do not include the <code>com.apple.security.get-task-allow</code> entitlement with the value set to any variation of true.

### M1048 - Application Isolation and Sandboxing

Ensure all COM alerts and Protected View are enabled.

### M1040 - Behavior Prevention on Endpoint

On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent DDE attacks and spawning of child processes from Office programs.

### M1042 - Disable or Remove Feature or Program

Registry keys specific to Microsoft Office feature control security can be set to disable automatic DDE/OLE execution. Microsoft also created, and enabled by default, Registry keys to completely disable DDE execution in Word and Excel.

### M1026 - Privileged Account Management

Modify Registry settings (directly or using Dcomcnfg.exe) in `HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\AppID\\{AppID_GUID}` associated with the process-wide security of individual COM applications.

Modify Registry settings (directly or using Dcomcnfg.exe) in `HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Ole` associated with system-wide security defaults for all COM applications that do no set their own process-wide security.

### M1054 - Software Configuration

Consider disabling embedded files in Office programs, such as OneNote, that do not work with Protected View.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0687 - Cyclops Blink

Cyclops Blink has the ability to create a pipe to enable inter-process communication.

### S1229 - Havoc

The Havoc SMB demon can use named pipes for communication through a parent demon.

### S0537 - HyperStack

HyperStack can connect to the IPC$ share on remote machines.

### S1141 - LunarWeb

LunarWeb can retrieve output from arbitrary processes and shell commands via a pipe.

### S1244 - Medusa Ransomware

Medusa Ransomware has leveraged the `CreatePipe` API to enable inter-process communication.

### S1100 - Ninja

Ninja can use pipes to redirect the standard input and the standard output.

### S1172 - OilBooster

OilBooster can read the results of command line execution via an unnamed pipe connected to the process.

### S1123 - PITSTOP

PITSTOP can listen over the Unix domain socket located at `/data/runtime/cockpit/wd.fd`.

### S1150 - ROADSWEEP

ROADSWEEP can pipe command output to a targeted process.

### S1130 - Raspberry Robin

Raspberry Robin contains an embedded custom Tor network client that communicates with the primary payload via shared process memory.

### S1078 - RotaJakiro

When executing with non-root permissions, RotaJakiro uses the the `shmget API` to create shared memory between other known RotaJakiro processes. This allows processes to communicate with each other and share their PID.

### S1200 - StealBit

StealBit can use interprocess communication (IPC) to enable the designation of multiple files for exfiltration in a scalable manner.

### S1239 - TONESHELL

TONESHELL has facilitated inter-process communication between DLL components via the use of pipes. TONESHELL has also created a reverse shell using two anonymous pipes to write data to stdin and read data from stdout and stderr.

### S0022 - Uroburos

Uroburos has the ability to move data between its kernel and user mode components, generally using named pipes.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0057 - 3CX Supply Chain Attack

During the 3CX Supply Chain Attack, AppleJeus's VEILEDSIGNAL creates and listens on a Windows named pipe to exchange messages between modules.

### C0048 - Operation MidnightEclipse

During Operation MidnightEclipse, threat actors wrote output to stdout then piped it to bash for execution.
