# T1200 - Hardware Additions

**Tactic:** Initial Access
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1200

## Description

Adversaries may physically introduce computer accessories, networking hardware, or other computing devices into a system or network that can be used as a vector to gain access. Rather than just connecting and distributing payloads via removable storage (i.e. Replication Through Removable Media), more robust hardware additions can be used to introduce new functionalities and/or features into a system that can then be abused.

While public references of usage by threat actors are scarce, many red teams/penetration testers leverage hardware additions for initial access. Commercial and open source products can be leveraged with capabilities such as passive network tapping, network traffic modification (i.e. Adversary-in-the-Middle), keystroke injection, kernel memory reading via DMA, addition of new wireless access points to an existing network, and others.

## Detection

### Detection Analytics

**Analytic 0185**

Chain: (1) a new external device is recognized by Windows (USB/Thunderbolt/PCIe) or a new block device appears; (2) within a short window, the same user/session spawns processes or the OS mounts a new volume; (3) optional follow-on activity such as HID keystroke injection, DMA driver load, or new network interface MAC on DHCP. Correlate Security EID 6416 / Kernel-PnP with sysmon and DHCP/network metadata.

**Analytic 0186**

Chain: (1) udev / kernel logs show hot-plug (USB/Thunderbolt/PCIe); (2) block device created by udisks/diskarbitration; (3) optional: new network interface or DHCP lease observed. Correlate /var/log/messages|syslog, auditd SYSCALL open/creat on /dev, and DHCP/Zeek.

**Analytic 0187**

Chain: (1) unified logs report IOUSBHost/IOThunderbolt device arrival; (2) diskarbitrationd attaches a new volume; (3) optional: config profile manipulation or new network interface MAC obtains a lease. Correlate unifiedlogs (subsystems: IOUSBHost, IOKit, diskarbitrationd), FSEvents, and DHCP/Zeek.


## Mitigations

### M1035 - Limit Access to Resource Over Network

Establish network access control policies, such as using device certificates and the 802.1x standard. Restrict use of DHCP to registered devices to prevent unregistered devices from communicating with trusted systems.

### M1034 - Limit Hardware Installation

Block unknown devices and accessories by endpoint security configuration and monitoring agent.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
