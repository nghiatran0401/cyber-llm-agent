# T1091 - Replication Through Removable Media

**Tactic:** Initial Access, Lateral Movement
**Platforms:** Windows
**Reference:** https://attack.mitre.org/techniques/T1091

## Description

Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes. In the case of Lateral Movement, this may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system. In the case of Initial Access, this may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself.

Mobile devices may also be used to infect PCs with malware if connected via USB. This infection may be achieved using devices (Android, iOS, etc.) and, in some instances, USB charging cables. For example, when a smartphone is connected to a system, it may appear to be mounted similar to a USB-connected disk drive. If malware that is compatible with the connected system is on the mobile device, the malware could infect the machine (especially if Autorun features are enabled).

## Detection

### Detection Analytics

**Analytic 0841**

Execution of files originating from removable media after drive mount, with correlation to file write activity, autorun usage, or lateral spread via staged tools.


## Mitigations

### M1040 - Behavior Prevention on Endpoint

On Windows 10, enable Attack Surface Reduction (ASR) rules to block unsigned/untrusted executable files (such as .exe, .dll, or .scr) from running from USB removable drives.

### M1042 - Disable or Remove Feature or Program

Disable Autorun if it is unnecessary. Disallow or restrict removable media at an organizational policy level if it is not required for business operations.

### M1034 - Limit Hardware Installation

Limit the use of USB devices and removable media within a network.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1074 - ANDROMEDA

ANDROMEDA has been spread via infected USB keys.

### S0092 - Agent.btz

Agent.btz drops itself onto removable media devices and creates an autorun.inf file with an instruction to run that file. When the device is inserted into another system, it opens autorun.inf and loads the malware.

### S0023 - CHOPSTICK

Part of APT28's operation involved using CHOPSTICK modules to copy itself to air-gapped machines and using files written to USB sticks to transfer data and command traffic.

### S0608 - Conficker

Conficker variants used the Windows AUTORUN feature to spread through USB propagation.

### S0115 - Crimson

Crimson can spread across systems by infecting removable media.

### S0062 - DustySky

DustySky searches for removable media and duplicates itself onto it.

### S0143 - Flame

Flame contains modules to infect USB sticks and spread laterally to other Windows systems the stick is plugged into using Autorun functionality.

### S0132 - H1N1

H1N1 has functionality to copy itself to removable media.

### S1230 - HIUPAN

HIUPAN has periodically checked for removable and hot-plugged drives connected to the infected machine, should one be found HIUPAN will propagate to the removeable drives by copying itself and accompanying malware components to a directory to the new drive in a hidden subdirectory `<Drive_Letter>:\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\` and hides any other existing files to ensure UsbConfig.exe is the only visible file on the device.

### S0013 - PlugX

PlugX has copied itself to infected removable drives for propagation to other victim devices.

### S0650 - QakBot

QakBot has the ability to use removable drives to spread through compromised networks.

### S0458 - Ramsay

Ramsay can spread itself by infecting other portable executable files on removable drives.

### S1130 - Raspberry Robin

Raspberry Robin has historically used infected USB media to spread to new victims.

### S0028 - SHIPSHAPE

APT30 may have used the SHIPSHAPE malware to move onto air-gapped networks. SHIPSHAPE targets removable drives to spread to other systems by modifying the drive to use Autorun to execute or by hiding legitimate document files and copying an executable to the folder with the same name as the legitimate document.

### S0603 - Stuxnet

Stuxnet can propagate via removable media using an autorun.inf file or the CVE-2010-2568 LNK vulnerability.

### S0136 - USBStealer

USBStealer drops itself onto removable media and relies on Autorun to execute the malicious file when a user opens the removable media on another system.

### S0452 - USBferry

USBferry can copy its installer to attached USB storage devices.

### S0130 - Unknown Logger

Unknown Logger is capable of spreading to USB devices.

### S0386 - Ursnif

Ursnif has copied itself to and infected removable drives for propagation.

### S0385 - njRAT

njRAT can be configured to spread via removable drives.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
