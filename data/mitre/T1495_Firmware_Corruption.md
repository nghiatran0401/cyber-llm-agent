# T1495 - Firmware Corruption

**Tactic:** Impact
**Platforms:** Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1495

## Description

Adversaries may overwrite or corrupt the flash memory contents of system BIOS or other firmware in devices attached to a system in order to render them inoperable or unable to boot, thus denying the availability to use the devices and/or the system. Firmware is software that is loaded and executed from non-volatile memory on hardware devices in order to initialize and manage device functionality. These devices may include the motherboard, hard drive, or video cards.

In general, adversaries may manipulate, overwrite, or corrupt firmware in order to deny the use of the system or devices. For example, corruption of firmware responsible for loading the operating system for network devices may render the network devices inoperable. Depending on the device, this attack may also result in Data Destruction.

## Detection

### Detection Analytics

**Analytic 0474**

Firmware flash utility invoked with elevated privileges followed by raw access to firmware device path or changes to boot configuration.

**Analytic 0475**

Direct write access to /dev/mem or /sys/firmware combined with usage of firmware flashing utilities (e.g., flashrom).

**Analytic 0476**

EFI updates executed via system processes or binaries outside of expected patch windows or using unsigned firmware packages.

**Analytic 0477**

Firmware image uploaded via TFTP/SCP or web interface followed by reboot or unexpected loss of connectivity.


## Mitigations

### M1046 - Boot Integrity

Check the integrity of the existing BIOS and device firmware to determine if it is vulnerable to modification.

### M1026 - Privileged Account Management

Prevent adversary access to privileged accounts or access necessary to replace system firmware.

### M1051 - Update Software

Patch the BIOS and other firmware as necessary to prevent successful use of known vulnerabilities.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0606 - Bad Rabbit

Bad Rabbit has used an executable that installs a modified bootloader to prevent normal boot-up.

### S0266 - TrickBot

TrickBot module "Trickboot" can write or erase the UEFI/BIOS firmware of a compromised device.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
