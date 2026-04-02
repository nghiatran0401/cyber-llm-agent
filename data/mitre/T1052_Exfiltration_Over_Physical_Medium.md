# T1052 - Exfiltration Over Physical Medium

**Tactic:** Exfiltration
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1052

## Description

Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a physical medium or device introduced by a user. Such media could be an external hard drive, USB drive, cellular phone, MP3 player, or other removable storage and processing device. The physical medium or device could be used as the final exfiltration point or to hop between otherwise disconnected systems.

## Detection

### Detection Analytics

**Analytic 0342**

Detects removable drive insertion followed by unusual file access, compression, or staging activity by unauthorized users or unexpected processes.

**Analytic 0343**

Detects mounted external devices (via /media or /mnt) followed by large file read or copy operations by shell scripts, unauthorized users, or staging tools (e.g., tar, rsync).

**Analytic 0344**

Detects mounting of external volumes followed by high-volume or sensitive file access via Finder, terminal, or third-party apps (e.g., rsync, zip).


## Mitigations

### M1057 - Data Loss Prevention

Data loss prevention can detect and block sensitive data being copied to physical mediums.

### M1042 - Disable or Remove Feature or Program

Disable Autorun if it is unnecessary. Disallow or restrict removable media at an organizational policy level if they are not required for business operations.

### M1034 - Limit Hardware Installation

Limit the use of USB devices and removable media within a network.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
