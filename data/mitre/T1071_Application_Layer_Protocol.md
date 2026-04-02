# T1071 - Application Layer Protocol

**Tactic:** Command and Control
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1071

## Description

Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. 

Adversaries may utilize many different protocols, including those used for web browsing, transferring files, electronic mail, DNS, or publishing/subscribing. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are SMB, SSH, or RDP.

## Detection

### Detection Analytics

**Analytic 1225**

Detects suspicious usage of common application-layer protocols (e.g., HTTP, HTTPS, DNS, SMB) by abnormal processes, with high outbound byte counts or irregular ports, possibly indicating command and control or data exfiltration.

**Analytic 1226**

Detects suspicious curl, wget, or custom socket traffic that leverages DNS, HTTPS, or IRC-style protocols with unbalanced traffic or beacon-like intervals.

**Analytic 1227**

Detects applications using abnormal protocols or high volume traffic not previously associated with the process image, such as Automator or AppleScript invoking curl or python sockets.

**Analytic 1228**

Detects application-layer tunneling or unauthorized app protocols like DNS-over-HTTPS, embedded C2 in TLS/HTTP headers, or misused SMB traffic crossing VLANs.


## Mitigations

### M1037 - Filter Network Traffic

Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic.

### M1031 - Network Intrusion Prevention

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0660 - Clambling

Clambling has the ability to use Telnet for communication.

### S0038 - Duqu

Duqu uses a custom command and control protocol that communicates over commonly used ports, and is frequently encapsulated by application layer protocols.

### S0601 - Hildegard

Hildegard has used an IRC channel for C2 communications.

### S0532 - Lucifer

Lucifer can use the Stratum protocol on port 10001 for communication between the cryptojacking bot and the mining server.

### S0034 - NETEAGLE

Adversaries can also use NETEAGLE to establish an RDP connection with a controller over TCP/7519.

### S1147 - Nightdoor

Nightdoor uses TCP and UDP communication for command and control traffic.

### S1084 - QUIETEXIT

QUIETEXIT can use an inverse negotiated SSH connection as part of its C2.

### S1130 - Raspberry Robin

Raspberry Robin is capable of contacting the TOR network for delivering second-stage payloads.

### S0623 - Siloscape

Siloscape connects to an IRC server for C2.

### S0633 - Sliver

Sliver can utilize the Wireguard VPN protocol for command and control.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0041 - FrostyGoop Incident

During FrostyGoop Incident, the adversary initiated Layer Two Tunnelling Protocol (L2TP) connections to Moscow-based IP addresses.
