# T1652 - Device Driver Discovery

**Tactic:** Discovery
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1652

## Description

Adversaries may attempt to enumerate local device drivers on a victim host. Information about device drivers may highlight various insights that shape follow-on behaviors, such as the function/purpose of the host, present security tools (i.e. Security Software Discovery) or other defenses (e.g., Virtualization/Sandbox Evasion), as well as potential exploitable vulnerabilities (e.g., Exploitation for Privilege Escalation).

Many OS utilities may provide information about local device drivers, such as `driverquery.exe` and the `EnumDeviceDrivers()` API function on Windows. Information about device drivers (as well as associated services, i.e., System Service Discovery) may also be available in the Registry.

On Linux/macOS, device drivers (in the form of kernel modules) may be visible within `/dev` or using utilities such as `lsmod` and `modinfo`.

## Detection

### Detection Analytics

**Analytic 1595**

Monitor for suspicious usage of driver enumeration utilities (driverquery.exe) or API calls such as EnumDeviceDrivers(). Registry queries against HKLM\SYSTEM\CurrentControlSet\Services and HardwareProfiles that are abnormal may also indicate attempts to discover installed drivers and services. Correlate command execution, process creation, and registry access to build a behavioral chain of driver discovery.

**Analytic 1596**

Detect attempts to enumerate kernel modules through lsmod, modinfo, or inspection of /proc/modules and /dev entries. Focus on unusual execution contexts such as unprivileged users or processes outside expected administrative workflows.

**Analytic 1597**

Detect loading or inspection of kernel extensions (kextstat, kextfind) and file access to /System/Library/Extensions/. Monitor unexpected usage of these utilities by non-administrative users or scripts.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0376 - HOPLIGHT

HOPLIGHT can enumerate device drivers located in the registry at `HKLM\Software\WBEM\WDM`.

### S1139 - INC Ransomware

INC Ransomware can verify the presence of specific drivers on compromised hosts including Microsoft Print to PDF and Microsoft XPS Document Writer.

### S0125 - Remsec

Remsec has a plugin to detect active drivers of some security products.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
