# T1074 - Data Staged

**Tactic:** Collection
**Platforms:** ESXi, IaaS, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1074

## Description

Adversaries may stage collected data in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Archive Collected Data. Interactive command shells may be used, and common functionality within cmd and bash may be used to copy data into a staging location.

In cloud environments, adversaries may stage data within a particular instance or virtual machine before exfiltration. An adversary may Create Cloud Instance and stage data in that instance.

Adversaries may choose to stage data from a victim network in a centralized location prior to Exfiltration to minimize the number of connections made to their C2 server and better evade detection.

## Detection

### Detection Analytics

**Analytic 0040**

Detects staging of sensitive files into temporary or public directories, compression with 7zip/WinRAR, or batch copy prior to exfiltration.

**Analytic 0041**

Detects script or user activity copying files to a central temp or /mnt directory followed by archive/compression utilities.

**Analytic 0042**

Detects files collected into user temp or shared directories followed by compression with ditto, zip, or custom scripts.

**Analytic 0043**

Detects virtual disk expansion or file copy operations to cloud buckets or mounted volumes from isolated instances.

**Analytic 0044**

Detects snapshots or data stored in VMFS volumes from root CLI or remote agents.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1020 - Kevin

Kevin can create directories to store logs and other collected data.

### S0641 - Kobalos

Kobalos can write captured SSH connection credentials to a file under the <code>/var/run</code> directory with a <code>.pid</code> extension for exfiltration.

### S1076 - QUIETCANARY

QUIETCANARY has the ability to stage data prior to exfiltration.

### S1019 - Shark

Shark has stored information in folders named `U1` and `U2` prior to exfiltration.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
