# T1025 - Data from Removable Media

**Tactic:** Collection
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1025

## Description

Adversaries may search connected removable media on computers they have compromised to find files of interest. Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prior to Exfiltration. Interactive command shells may be in use, and common functionality within cmd may be used to gather information. 

Some adversaries may also use Automated Collection on removable media.

## Detection

### Detection Analytics

**Analytic 1410**

Adversary mounts a USB device and begins enumerating, copying, or compressing files using scripting engines, cmd, or remote access tools.

**Analytic 1411**

Adversary mounts external drive to /media or /mnt then accesses or copies targeted data via shell, cp, or tar.

**Analytic 1412**

Adversary attaches USB drive and accesses sensitive files using Finder, cp, or bash scripts.


## Mitigations

### M1057 - Data Loss Prevention

Data loss prevention can restrict access to sensitive data and detect sensitive data that is unencrypted.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0622 - AppleSeed

AppleSeed can find and collect data from removable media devices.

### S0456 - Aria-body

Aria-body has the ability to collect data from USB devices.

### S0128 - BADNEWS

BADNEWS copies files with certain extensions from USB devices to
a predefined directory.

### S0050 - CosmicDuke

CosmicDuke steals user files from removable media with file extensions and keywords that match a predefined list.

### S0115 - Crimson

Crimson contains a module to collect data from removable drives.

### S0538 - Crutch

Crutch can monitor removable drives and exfiltrate files matching a given extension list.

### S0569 - Explosive

Explosive can scan all .exe files located in the USB drive.

### S0036 - FLASHFLOOD

FLASHFLOOD searches for interesting files (either a default or customized set of file extensions) on removable media and copies them to a staging area. The default file types copied would include data copied to the drive by SPACESHIP.

### S1044 - FunnyDream

The FunnyDream FilePakMonitor component has the ability to collect files from removable devices.

### S0237 - GravityRAT

GravityRAT steals files based on an extension list if a USB drive is connected to the system.

### S0260 - InvisiMole

InvisiMole can collect jpeg files from connected MTP devices.

### S0409 - Machete

Machete can find, encrypt, and upload files from fixed and removable drives.

### S1146 - MgBot

MgBot includes modules capable of gathering information from USB thumb drives and CD-ROMs on the victim machine given a list of provided criteria.

### S0644 - ObliqueRAT

ObliqueRAT has the ability to extract data from removable devices connected to the endpoint.

### S0113 - Prikormka

Prikormka contains a module that collects documents with certain extensions from removable media or fixed drives connected via USB.

### S0458 - Ramsay

Ramsay can collect data from removable media and stage it for exfiltration.

### S0125 - Remsec

Remsec has a package that collects documents from any inserted USB sticks.

### S0090 - Rover

Rover searches for files on attached removable drives based on a predefined list of file extensions every five seconds.

### S0467 - TajMahal

TajMahal has the ability to steal written CD images and files of interest from previously connected removable drives when they become available again.

### S0136 - USBStealer

Once a removable media device is inserted back into the first victim, USBStealer collects data from it that was exfiltrated from a second victim.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
