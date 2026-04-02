# T1601 - Modify System Image

**Tactic:** Defense Evasion
**Platforms:** Network Devices
**Reference:** https://attack.mitre.org/techniques/T1601

## Description

Adversaries may make changes to the operating system of embedded network devices to weaken defenses and provide new capabilities for themselves.  On such devices, the operating systems are typically monolithic and most of the device functionality and capabilities are contained within a single file.

To change the operating system, the adversary typically only needs to affect this one file, replacing or modifying it.  This can either be done live in memory during system runtime for immediate effect, or in storage to implement the change on the next boot of the network device.

## Detection

### Detection Analytics

**Analytic 0482**

Defenders may observe adversary attempts to alter or replace a network device’s operating system image through anomalous CLI commands, unexpected firmware updates, integrity check failures, or mismatches in version and checksum validation. Suspicious behavior includes modification of image files on storage, OS version output inconsistent with baselines, unexpected reloads or reboots after image replacement, and changes to boot configuration that load non-standard system images.


## Mitigations

### M1046 - Boot Integrity

Some vendors of embedded network devices provide cryptographic signing to ensure the integrity of operating system images at boot time.  Implement where available, following vendor guidelines.

### M1045 - Code Signing

Many vendors provide digitally signed operating system images to validate the integrity of the software used on their platform.  Make use of this feature where possible in order to prevent and/or detect attempts by adversaries to compromise the system image.

### M1043 - Credential Access Protection

Some embedded network devices are capable of storing passwords for local accounts in either plain-text or encrypted formats.  Ensure that, where available, local passwords are always encrypted, per vendor recommendations.

### M1032 - Multi-factor Authentication

Use multi-factor authentication for user and privileged accounts. Most embedded network devices support TACACS+ and/or RADIUS.  Follow vendor prescribed best practices for hardening access control.

### M1027 - Password Policies

Refer to NIST guidelines when creating password policies.

### M1026 - Privileged Account Management

Restrict administrator accounts to as few individuals as possible, following least privilege principles.  Prevent credential overlap across systems of administrator and privileged accounts, particularly between network and non-network platforms, such as servers or endpoints.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
