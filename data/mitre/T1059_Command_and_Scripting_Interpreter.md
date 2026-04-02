# T1059 - Command and Scripting Interpreter

**Tactic:** Execution
**Platforms:** ESXi, IaaS, Identity Provider, Linux, Network Devices, Office Suite, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1059

## Description

Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of Unix Shell while Windows installations include the Windows Command Shell and PowerShell.

There are also cross-platform interpreters such as Python, as well as those commonly associated with client applications such as JavaScript and Visual Basic.

Adversaries may abuse these technologies in various ways as a means of executing arbitrary commands. Commands and scripts can be embedded in Initial Access payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. Adversaries may also execute commands through interactive terminals/shells, as well as utilize various Remote Services in order to achieve remote Execution.

## Detection

### Detection Analytics

**Analytic 1428**

Detects the execution of scripting or command interpreters (e.g., powershell.exe, cmd.exe, wscript.exe) outside expected administrative time windows or from abnormal user contexts, often followed by encoded/obfuscated arguments or secondary execution events.

**Analytic 1429**

Detects use of shell interpreters (e.g., bash, sh, python, perl) initiated by users or processes not normally executing them, especially when chaining suspicious utilities like netcat, curl, or ssh.

**Analytic 1430**

Detects launch of command-line interpreters via Terminal, Automator, or hidden `osascript`, especially when parent process lineage deviates from user-initiated applications.

**Analytic 1431**

Detects use of 'esxcli system' or direct interpreter commands (e.g., busybox shell) invoked from SSH or host terminal unexpectedly.

**Analytic 1432**

Identifies CLI interpreter access (e.g., Cisco IOS, Juniper JUNOS) via `enable` mode or scripting-capable sessions used by uncommon accounts or from unknown IPs.


## Mitigations

### M1049 - Antivirus/Antimalware

Anti-virus can be used to automatically quarantine suspicious files.

### M1047 - Audit

Inventory systems for unauthorized command and scripting interpreter installations.

### M1040 - Behavior Prevention on Endpoint

On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent Visual Basic and JavaScript scripts from executing potentially malicious downloaded content.

### M1045 - Code Signing

Where possible, only permit execution of signed scripts.

### M1042 - Disable or Remove Feature or Program

Disable or remove any unnecessary or unused shells or interpreters.

### M1038 - Execution Prevention

Use application control where appropriate. For example, PowerShell Constrained Language mode can be used to restrict access to sensitive or otherwise dangerous language elements such as those used to execute arbitrary Windows APIs or files (e.g., `Add-Type`).

### M1033 - Limit Software Installation

Prevent user installation of unrequired command and scripting interpreters.

### M1026 - Privileged Account Management

When PowerShell is necessary, consider restricting PowerShell execution policy to administrators. Be aware that there are methods of bypassing the PowerShell execution policy, depending on environment configuration.

PowerShell JEA (Just Enough Administration) may also be used to sandbox administration and limit what commands admins/users can execute through remote PowerShell sessions.

### M1021 - Restrict Web-Based Content

Script blocking extensions can help prevent the execution of scripts and HTA files that may commonly be used during the exploitation process. For malicious code served up through ads, adblockers can help prevent that code from executing in the first place.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0234 - Bandook

Bandook can support commands to execute Java-based payloads.

### S0486 - Bonadan

Bonadan can create bind and reverse shells on the infected system.

### S0023 - CHOPSTICK

CHOPSTICK is capable of performing remote command execution.

### S0334 - DarkComet

DarkComet can execute various types of scripts on the victim’s machine.

### S0695 - Donut

Donut can generate shellcode outputs that execute via Ruby.

### S0363 - Empire

Empire uses a command-line interface to interact with systems.

### S0618 - FIVEHANDS

FIVEHANDS can receive a command line argument to limit file encryption to specified directories.

### S0460 - Get2

Get2 has the ability to run executables with command-line arguments.

### S0434 - Imminent Monitor

Imminent Monitor has a CommandPromptPacket and ScriptPacket module(s) for creating a remote shell and executing scripts.

### S0487 - Kessel

Kessel can create a reverse shell between the infected host and a specified system.

### S0167 - Matryoshka

Matryoshka is capable of providing Meterpreter shell access.

### S1192 - NICECURL

NICECURL has provided an arbitrary command execution interface.

### S0598 - P.A.S. Webshell

P.A.S. Webshell has the ability to create reverse shells with Perl scripts.

### S1130 - Raspberry Robin

Raspberry Robin variants can be delivered via highly obfuscated Windows Script Files (WSF) for initial execution.

### S1110 - SLIGHTPULSE

SLIGHTPULSE contains functionality to execute arbitrary commands passed to it.

### S0374 - SpeakUp

SpeakUp uses Perl scripts.

### S1227 - StarProxy

StarProxy has used the command line for execution of commands.

### S1154 - VersaMem

VersaMem was delivered as a Java Archive (JAR) that runs by attaching itself to the Apache Tomcat Java servlet and web server.

### S0219 - WINERACK

WINERACK can create a reverse shell that utilizes statically-linked Wine cmd.exe code to emulate Windows command prompt commands.

### S1151 - ZeroCleare

ZeroCleare can receive command line arguments from an operator to corrupt the file system using the RawDisk driver.

### S0330 - Zeus Panda

Zeus Panda can launch remote scripts on the victim’s machine.

### S0032 - gh0st RAT

gh0st RAT is able to open a remote shell to execute commands.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0046 - ArcaneDoor

ArcaneDoor included the adversary executing command line interface (CLI) commands.

### C0029 - Cutting Edge

During Cutting Edge, threat actors used Perl scripts to enable the deployment of the THINSPOOL shell script dropper and for enumerating host data.

### C0053 - FLORAHOX Activity

FLORAHOX Activity has executed PHP and Shell scripts to identify and infect subsequent routers for the ORB network.

### C0005 - Operation Spalax

For Operation Spalax, the threat actors used Nullsoft Scriptable Install System (NSIS) scripts to install malware.
