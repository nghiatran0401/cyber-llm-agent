# T1653 - Power Settings

**Tactic:** Persistence
**Platforms:** Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1653

## Description

Adversaries may impair a system's ability to hibernate, reboot, or shut down in order to extend access to infected machines. When a computer enters a dormant state, some or all software and hardware may cease to operate which can disrupt malicious activity.

Adversaries may abuse system utilities and configuration settings to maintain access by preventing machines from entering a state, such as standby, that can terminate malicious activity.

For example, `powercfg` controls all configurable power system settings on a Windows system and can be abused to prevent an infected host from locking or shutting down. Adversaries may also extend system lock screen timeout settings. Other relevant settings, such as disk and hibernate timeout, can be similarly abused to keep the infected machine running even if no user is active.

Aware that some malware cannot survive system reboots, adversaries may entirely delete files used to invoke system shut down or reboot.

## Detection

### Detection Analytics

**Analytic 1174**

Monitor command execution of powercfg.exe with arguments modifying sleep, hibernate, or display timeouts. Abnormal or repeated modifications to power settings outside administrative baselines may indicate persistence attempts. Correlate process creation with registry and system configuration changes to build behavioral chains.

**Analytic 1175**

Detect execution of system utilities (systemctl, systemd-inhibit, systemdsleep) modifying sleep or hibernate behavior. Abnormal edits to system configuration files (e.g., /etc/systemd/sleep.conf) should be correlated with process execution to identify persistence techniques.

**Analytic 1176**

Monitor pmset command executions altering sleep/hibernate/standby parameters. Unexpected modifications to /Library/Preferences/SystemConfiguration/com.apple.PowerManagement.plist or similar files should be correlated with process activity.


## Mitigations

### M1047 - Audit

Periodically inspect systems for abnormal and unexpected power settings that may indicate malicious activty.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1186 - Line Dancer

Line Dancer can modify the crash dump process on infected machines to skip crash dump generation and proceed directly to device reboot for both persistence and forensic evasion purposes.

### S1188 - Line Runner

Line Runner used CVE-2024-20353 to trigger victim devices to reboot, in the process unzipping and installing the Line Dancer payload.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0046 - ArcaneDoor

ArcaneDoor involved exploitation of CVE-2024-20353 to force a victim Cisco ASA to reboot, triggering the automated unzipping and execution of the Line Runner implant.
