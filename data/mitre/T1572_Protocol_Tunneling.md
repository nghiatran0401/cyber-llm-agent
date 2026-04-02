# T1572 - Protocol Tunneling

**Tactic:** Command and Control
**Platforms:** ESXi, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1572

## Description

Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems. Tunneling involves explicitly encapsulating a protocol within another. This behavior may conceal malicious traffic by blending in with existing traffic and/or provide an outer layer of encryption (similar to a VPN). Tunneling could also enable routing of network packets that would otherwise not reach their intended destination, such as SMB, RDP, or other traffic that would be filtered by network appliances or not routed over the Internet. 

There are various means to encapsulate a protocol within another protocol. For example, adversaries may perform SSH tunneling (also known as SSH port forwarding), which involves forwarding arbitrary data over an encrypted SSH tunnel. 

Protocol Tunneling may also be abused by adversaries during Dynamic Resolution. Known as DNS over HTTPS (DoH), queries to resolve C2 infrastructure may be encapsulated within encrypted HTTPS packets. 

Adversaries may also leverage Protocol Tunneling in conjunction with Proxy and/or Protocol or Service Impersonation to further conceal C2 communications and infrastructure.

## Detection

### Detection Analytics

**Analytic 1483**

Processes such as plink.exe, ssh.exe, or netsh.exe establishing outbound network connections where traffic patterns show encapsulated protocols (e.g., RDP over SSH). Defender observations include anomalous process-to-network relationships, large asymmetric data flows, and port usage mismatches.

**Analytic 1484**

sshd, socat, or custom binaries initiating port forwarding or encapsulating traffic (e.g., RDP, SMB) through SSH or HTTP. Defender sees abnormal connect/bind syscalls, encrypted traffic on ports typically used for non-encrypted services, and outlier traffic volume patterns.

**Analytic 1485**

launchd or user-invoked processes (ssh, socat) encapsulating traffic via SSH tunnels, VPN-style tooling, or DNS-over-HTTPS clients. Defender sees outbound TLS traffic with embedded DNS or RDP payloads.

**Analytic 1486**

VMware daemons or user processes encapsulating traffic (e.g., guest VMs tunneling via hostd). Defender sees network services inside ESXi creating flows inconsistent with management plane traffic, such as SSH forwarding or DNS-over-HTTPS from management interfaces.


## Mitigations

### M1037 - Filter Network Traffic

Consider filtering network traffic to untrusted or known bad domains and resources.

### M1031 - Network Intrusion Prevention

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1063 - Brute Ratel C4

Brute Ratel C4 can use DNS over HTTPS for C2.

### S0154 - Cobalt Strike

Cobalt Strike uses a custom command and control protocol that is encapsulated in HTTP, HTTPS, or DNS. In addition, it conducts peer-to-peer communication over Windows named pipes encapsulated in the SMB protocol. All protocols use their standard assigned ports.

### S0687 - Cyclops Blink

Cyclops Blink can use DNS over HTTPS (DoH) to resolve C2 nodes.

### S0038 - Duqu

Duqu uses a custom command and control protocol that communicates over commonly used ports, and is frequently encapsulated by application layer protocols.

### S0173 - FLIPSIDE

FLIPSIDE uses RDP to tunnel traffic from a victim environment.

### S1144 - FRP

FRP can tunnel SSH and Unix Domain Socket communications over TCP between external nodes and exposed resources behind firewalls or NAT.

### S1044 - FunnyDream

FunnyDream can connect to HTTP proxies via TCP to create a tunnel to C2.

### S1027 - Heyoka Backdoor

Heyoka Backdoor can use spoofed DNS requests to create a bidirectional tunnel between a compromised host and its C2 servers.

### S0604 - Industroyer

Industroyer attempts to perform an HTTP CONNECT via an internal proxy to establish a tunnel.

### S1020 - Kevin

Kevin can use a custom protocol tunneled through DNS or HTTP.

### S1141 - LunarWeb

LunarWeb can run a custom binary protocol under HTTPS for C2.

### S1015 - Milan

Milan can use a custom protocol tunneled through DNS or HTTP.

### S0699 - Mythic

Mythic can use SOCKS proxies to tunnel traffic through another protocol.

### S1189 - Neo-reGeorg

Neo-reGeorg can tunnel data in and out of targeted networks.

### S0650 - QakBot

The QakBot proxy module can encapsulate SOCKS5 protocol within its own proxy protocol.

### S0022 - Uroburos

Uroburos has the ability to communicate over custom communications methodologies that ride over common network protocols including raw TCP and UDP sockets, HTTP, SMTP, and DNS.

### S0508 - ngrok

ngrok can tunnel RDP and other services securely over internet connections.

### S1187 - reGeorg

reGeorg can tunnel TCP sessions including RDP, SSH, and SMB through HTTP.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0034 - 2022 Ukraine Electric Power Attack

During the 2022 Ukraine Electric Power Attack, Sandworm Team deployed the GOGETTER tunneler software to establish a “Yamux” TLS-based C2 channel with an external server(s).

### C0027 - C0027

During C0027, Scattered Spider used SSH tunneling in targeted environments.

### C0032 - C0032

During the C0032 campaign, TEMP.Veles used encrypted SSH-based PLINK tunnels to transfer tools and enable RDP connections throughout the environment.

### C0004 - CostaRicto

During CostaRicto, the threat actors set up remote SSH tunneling into the victim's environment from a malicious domain.

### C0029 - Cutting Edge

During Cutting Edge, threat actors used Iodine to tunnel IPv4 traffic over DNS.

### C0058 - SharePoint ToolShell Exploitation

During SharePoint ToolShell Exploitation, threat actors utilized ngrok tunnels to deliver PowerShell payloads.
