# T1669 - Wi-Fi Networks

**Tactic:** Initial Access
**Platforms:** Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1669

## Description

Adversaries may gain initial access to target systems by connecting to wireless networks. They may accomplish this by exploiting open Wi-Fi networks used by target devices or by accessing secured Wi-Fi networks — requiring Valid Accounts — belonging to a target organization. Establishing a connection to a Wi-Fi access point requires a certain level of proximity to both discover and maintain a stable network connection. 

Adversaries may establish a wireless connection through various methods, such as by physically positioning themselves near a Wi-Fi network to conduct close access operations. To bypass the need for physical proximity, adversaries may attempt to remotely compromise nearby third-party systems that have both wired and wireless network connections available (i.e., dual-homed systems). These third-party compromised devices can then serve as a bridge to connect to a target’s Wi-Fi network.

Once an initial wireless connection is achieved, adversaries may leverage this access for follow-on activities in the victim network or further targeting of specific devices on the network. Adversaries may perform Network Sniffing or Adversary-in-the-Middle activities for Credential Access or Discovery.

## Detection

### Detection Analytics

**Analytic 1476**

Detects anomalous wireless connections such as unexpected SSID associations, failed or repeated authentication attempts, and connections outside of known geofenced networks. Defenders should monitor wireless connection logs and event codes for network discovery, authentication, and association events.

**Analytic 1477**

Detects unauthorized wireless associations by monitoring wpa_supplicant logs, NetworkManager events, and system calls related to interface state changes. Anomalies include repeated association failures, new SSIDs outside baselined values, and rogue AP connections.

**Analytic 1478**

Detects unauthorized Wi-Fi associations and SSID scanning activity using unified logs and airport command telemetry. Anomalies include rapid SSID switching, connections to unapproved SSIDs, or repeated authentication failures.

**Analytic 1479**

Detects rogue or suspicious wireless access attempts by monitoring firewall, WIDS/WIPS, and controller logs. Focus is on firewall rule changes, rogue AP detection, and anomalous MAC addresses connecting to access points.


## Mitigations

### M1041 - Encrypt Sensitive Information

Ensure that all wired and/or wireless traffic is encrypted appropriately. Use best practices for authentication protocols, such as Kerberos, and ensure that web traffic that may contain credentials is protected by SSL/TLS.

### M1032 - Multi-factor Authentication

Harden access requirements for Wi-Fi networks through using two or more pieces of evidence to authenticate, such as a username and password in addition to a token from a physical smart card or token generator.

### M1030 - Network Segmentation

Network segmentation can be used to isolate infrastructure components that do not require broad network access. Separate networking environments for Wi-Fi and Ethernet-wired networks, particularly where Ethernet-based networks allow for access to sensitive resources.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

### C0051 - APT28 Nearest Neighbor Campaign

During APT28 Nearest Neighbor Campaign, APT28 established wireless connections to secure, enterprise Wi-Fi networks belonging to a target organization for initial access into the environment.
