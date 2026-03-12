# T1497 - Virtualization/Sandbox Evasion

**Tactic:** Defense Evasion, Discovery
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1497

## Description

Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors.

Adversaries may use several methods to accomplish Virtualization/Sandbox Evasion such as checking for security monitoring tools (e.g., Sysinternals, Wireshark, etc.) or other system artifacts associated with analysis or virtualization. Adversaries may also check for legitimate user activity to help determine if it is in an analysis environment. Additional methods include use of sleep timers or loops within malware code to avoid operating within a temporary sandbox.

## Detection

### Detection Analytics

**Analytic 0127**

Execution of discovery commands or API calls for virtualization artifacts (e.g., registry keys, device drivers, services), sleep/skipped execution behavior, or sandbox evasion DLLs before payload deployment.

**Analytic 0128**

Execution of commands to enumerate virtualization-related files or processes (e.g., '/sys/class/dmi/id/product_name', dmesg, lscpu, lspci), or querying hypervisor interfaces prior to malware execution.

**Analytic 0129**

Execution of scripts or binaries that check for virtualization indicators (e.g., system_profiler, ioreg -l, kextstat), combined with delay functions or anomalous launchd activity.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0331 - Agent Tesla

Agent Tesla has the ability to perform anti-sandboxing and anti-virtualization checks.

### S0534 - Bazar

Bazar can attempt to overload sandbox analysis by sending 1550 calls to <code>printf</code>.

### S0268 - Bisonal

Bisonal can check to determine if the compromised system is running on VMware.

### S1070 - Black Basta

Black Basta can make a random number of calls to the `kernel32.beep` function to hinder log analysis.

### S1039 - Bumblebee

Bumblebee has the ability to perform anti-virtualization checks.

### S0023 - CHOPSTICK

CHOPSTICK  includes runtime checks to identify an analysis environment and prevent execution on it.

### S0484 - Carberp

Carberp has removed various hooks before installing the trojan or bootkit to evade sandbox analysis or other analysis software.

### S0046 - CozyCar

Some versions of CozyCar will check to ensure it is not being executed inside a virtual machine or a known malware analysis sandbox environment. If it detects that it is, it will exit.

### S0554 - Egregor

Egregor has used multiple anti-analysis and anti-sandbox techniques to prevent automated analysis by sandboxes.

### S0666 - Gelsemium

Gelsemium can use junk code to generate random activity to obscure malware behavior.

### S0499 - Hancitor

Hancitor has used a macro to check that an ActiveDocument shape object in the lure message is present. If this object is not found, the macro will exit without downloading additional payloads.

### S0483 - IcedID

IcedID has manipulated Keitaro Traffic Direction System to filter researcher and sandbox traffic.

### S1020 - Kevin

Kevin can sleep for a time interval between C2 communication attempts.

### S0455 - Metamorfo

Metamorfo has embedded a "vmdetect.exe" executable to identify virtual machines at the beginning of execution.

### S0147 - Pteranodon

Pteranodon has the ability to use anti-detection functions to identify sandbox environments.

### S0148 - RTM

RTM can detect if it is running within a sandbox or other virtualized analysis environment.

### S1130 - Raspberry Robin

Raspberry Robin contains real and fake second-stage payloads following initial execution, with the real payload only delivered if the malware determines it is not running in a virtualized environment.

### S1240 - RedLine Stealer

RedLine Stealer has an anti-sandbox technique that requires the malware to consistently check with the C2 server, if the communication fails RedLine Stealer will not continue execution.

### S1030 - Squirrelwaffle

Squirrelwaffle has contained a hardcoded list of IP addresses to block that belong to sandboxes and analysis platforms.

### S0380 - StoneDrill

StoneDrill has used several anti-emulation techniques to prevent automated analysis by emulators or sandboxes.

### S1183 - StrelaStealer

StrelaStealer payloads have used control flow obfuscation techniques such as excessively long code blocks of mathematical instructions to defeat sandboxing and related analysis methods.

### S1207 - XLoader

XLoader can utilize decoy command and control domains within the malware configuration to circumvent sandbox analysis.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0005 - Operation Spalax

During Operation Spalax, the threat actors used droppers that would run anti-analysis checks before executing malware on a compromised host.
