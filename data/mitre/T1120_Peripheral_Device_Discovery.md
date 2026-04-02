# T1120 - Peripheral Device Discovery

**Tactic:** Discovery
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1120

## Description

Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system. Peripheral devices could include auxiliary resources that support a variety of functionalities such as keyboards, printers, cameras, smart card readers, or removable storage. The information may be used to enhance their awareness of the system and network environment or may be used for further actions.

## Detection

### Detection Analytics

**Analytic 1353**

Suspicious enumeration of attached peripherals via WMI, PowerShell, or low-level API calls potentially chained with removable device interactions.

**Analytic 1354**

Enumeration of USB and other peripheral hardware via udevadm, lshw, or /sys or /proc interfaces in proximity to collection or mounting behavior.

**Analytic 1355**

Execution of system utilities like 'system_profiler' and 'ioreg' to enumerate hardware components or USB devices, particularly if followed by clipboard, file, or network activity.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0045 - ADVSTORESHELL

ADVSTORESHELL can list connected devices.

### S1167 - AcidPour

AcidPour includes functionality to identify MMC and SD cards connected to the victim device.

### S0438 - Attor

Attor has a plugin that collects information about inserted storage devices, modems, and phone devices.

### S0128 - BADNEWS

BADNEWS checks for new hard drives on the victim, such as USB devices, by listening for the WM_DEVICECHANGE window message.

### S0234 - Bandook

Bandook can detect USB devices.

### S0089 - BlackEnergy

BlackEnergy can gather very specific information about attached USB devices, to include device instance ID and drive geometry.

### S1149 - CHIMNEYSWEEP

CHIMNEYSWEEP can monitor for removable drives.

### S0454 - Cadelspy

Cadelspy has the ability to steal information about printers and the documents sent to printers.

### S0115 - Crimson

Crimson has the ability to discover pluggable/removable drives to extract files from.

### S0538 - Crutch

Crutch can monitor for removable drives being plugged into the compromised machine.

### S0673 - DarkWatchman

DarkWatchman can list signed PnP drivers for smartcard readers.

### S0062 - DustySky

DustySky can detect connected USB devices.

### S0679 - Ferocious

Ferocious can run <code>GET.WORKSPACE</code> in Microsoft Excel to check if a mouse is present.

### S0381 - FlawedAmmyy

FlawedAmmyy will attempt to detect if a usable smart card is current inserted into a card reader.

### S1044 - FunnyDream

The FunnyDream FilepakMonitor component can detect removable drive insertion.

### S1230 - HIUPAN

HIUPAN has checked periodically for removable drives and installs itself when a drive is detected.

### S1027 - Heyoka Backdoor

Heyoka Backdoor can identify removable media attached to victim's machines.

### S1139 - INC Ransomware

INC Ransomware can identify external USB and hard drives for encryption and printers to print ransom notes.

### S1199 - LockBit 2.0

LockBit 2.0 has the ability to identify mounted external storage devices.

### S1202 - LockBit 3.0

LockBit 3.0 has the ability to discover external storage devices.

### S0409 - Machete

Machete detects the insertion of new devices by listening for the WM_DEVICECHANGE window message.

### S1026 - Mongall

Mongall can identify removable media attached to compromised hosts.

### S0149 - MoonWind

MoonWind obtains the number of removable drives from the victim.

### S1090 - NightClub

NightClub has the ability to monitor removable drives.

### S0644 - ObliqueRAT

ObliqueRAT can discover pluggable/removable drives to extract files from.

### S0013 - PlugX

PlugX can identify removable media attached to compromised hosts.

### S0113 - Prikormka

A module in Prikormka collects information on available printers and disk drives.

### S0650 - QakBot

QakBot can identify peripheral devices on targeted systems.

### S0686 - QuietSieve

QuietSieve can identify and search removable drives for specific file name extensions.

### S1150 - ROADSWEEP

ROADSWEEP can identify removable drives attached to the victim's machine.

### S0148 - RTM

RTM can obtain a list of smart card readers attached to the victim.

### S0481 - Ragnar Locker

Ragnar Locker may attempt to connect to removable drives and mapped network drives.

### S0458 - Ramsay

Ramsay can scan for removable media which may contain documents for collection.

### S1064 - SVCReady

SVCReady can check for the number of devices plugged into an infected host.

### S1089 - SharpDisco

SharpDisco has dropped a plugin to monitor external drives to `C:\Users\Public\It3.exe`.

### S0603 - Stuxnet

Stuxnet enumerates removable drives for infection.

### S0098 - T9000

T9000 searches through connected drives for removable storage devices.

### S0467 - TajMahal

TajMahal has the ability to identify connected Apple devices.

### S0647 - Turian

Turian can scan for removable media to collect data.

### S0136 - USBStealer

USBStealer monitors victims for insertion of removable drives. When dropped onto a second victim, it also enumerates drives connected to the system.

### S0452 - USBferry

USBferry can check for connected USB devices.

### S0366 - WannaCry

WannaCry contains a thread that will attempt to scan for new attached drives every few seconds. If one is identified, it will encrypt the files on the attached device.

### S0612 - WastedLocker

WastedLocker can enumerate removable drives prior to the encryption process.

### S0251 - Zebrocy

Zebrocy enumerates information about connected storage devices.

### S0283 - jRAT

jRAT can map UPnP ports.

### S0385 - njRAT

njRAT will attempt to detect if the victim system has a camera during the initial infection. njRAT can also detect any removable drives connected to the system.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0012 - Operation CuckooBees

During Operation CuckooBees, the threat actors used the `fsutil fsinfo drives` command as part of their advanced reconnaissance.

### C0014 - Operation Wocao

During Operation Wocao, threat actors discovered removable disks attached to a system.
