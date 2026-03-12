# T1092 - Communication Through Removable Media

**Tactic:** Command and Control
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1092

## Description

Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system. Both systems would need to be compromised, with the likelihood that an Internet-connected system was compromised first and the second through lateral movement by Replication Through Removable Media. Commands and files would be relayed from the disconnected system to the Internet-connected system to which the adversary has direct access.

## Detection

### Detection Analytics

**Analytic 0247**

Behavioral sequence where removable media is mounted, files are written/updated, and subsequently read/executed on a separate host, suggesting removable-media relay communication.

**Analytic 0248**

Detection of file write-access to USB-mount directories (e.g., /media/, /run/media/) followed by same-file access or execution on another host.

**Analytic 0249**

Correlates removable volume mounts (disk arbitration) with file I/O events on that volume, followed by same file execution shortly after insert.


## Mitigations

### M1042 - Disable or Remove Feature or Program

Disable Autoruns if it is unnecessary.

### M1028 - Operating System Configuration

Disallow or restrict removable media at an organizational policy level if they are not required for business operations.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0023 - CHOPSTICK

Part of APT28's operation involved using CHOPSTICK modules to copy itself to air-gapped machines, using files written to USB sticks to transfer data and command traffic.

### S0136 - USBStealer

USBStealer drops commands for a second victim onto a removable media drive inserted into the first victim, and commands are executed when the drive is inserted into the second victim.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
