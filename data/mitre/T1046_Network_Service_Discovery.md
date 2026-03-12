# T1046 - Network Service Discovery

**Tactic:** Discovery
**Platforms:** Containers, IaaS, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1046

## Description

Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port, vulnerability, and/or wordlist scans using tools that are brought onto a system.   

Within cloud environments, adversaries may attempt to discover services running on other cloud hosts. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems as well.

Within macOS environments, adversaries may use the native Bonjour application to discover services running on other macOS hosts within a network. The Bonjour mDNSResponder daemon automatically registers and advertises a host’s registered services on the network. For example, adversaries can use a mDNS query (such as <code>dns-sd -B _ssh._tcp .</code>) to find other systems broadcasting the ssh service.

## Detection

### Detection Analytics

**Analytic 1057**

Detects processes performing network enumeration (e.g., port scans, service probing) by correlating process creation, socket connections, and sequential destination IP probing within a time window.

**Analytic 1058**

Detects use of network scanning utilities or scripts performing rapid connections to multiple services or hosts using auditd and netflow/pcap telemetry.

**Analytic 1059**

Detects Bonjour-based mDNS enumeration or use of system tools (e.g., dns-sd, nmap) to find active services via multicast probing or targeted scans.

**Analytic 1060**

Detects lateral discovery or container breakout attempts using netcat, curl, or custom binaries probing other services within the same namespace or VPC subnet.


## Mitigations

### M1042 - Disable or Remove Feature or Program

Ensure that unnecessary ports and services are closed to prevent risk of discovery and potential exploitation.

### M1031 - Network Intrusion Prevention

Use network intrusion detection/prevention systems to detect and prevent remote service scans.

### M1030 - Network Segmentation

Ensure proper network segmentation is followed to protect critical servers and devices.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1081 - BADHATCH

BADHATCH can check for open ports on a computer by establishing a TCP connection.

### S0093 - Backdoor.Oldrea

Backdoor.Oldrea can use a network scanning module to identify ICS-related ports.

### S1180 - BlackByte Ransomware

BlackByte Ransomware identifies remote systems via active directory queries for hostnames prior to launching remote ransomware payloads.

### S0089 - BlackEnergy

BlackEnergy has conducted port scans on a host.

### S1063 - Brute Ratel C4

Brute Ratel C4 can conduct port scanning against targeted systems.

### S0572 - Caterpillar WebShell

Caterpillar WebShell has a module to use a port scanner on a system.

### S0020 - China Chopper

China Chopper's server component can spider authentication portals.

### S0154 - Cobalt Strike

Cobalt Strike can perform port scans from an infected host.

### S0608 - Conficker

Conficker scans for other machines to infect.

### S0363 - Empire

Empire can perform port scans from an infected host.

### S1144 - FRP

As part of load balancing FRP can set `healthCheck.type = "tcp"` or `healthCheck.type = "http"` to check service status on specific hosts with TCPing or an HTTP request.

### S0061 - HDoor

HDoor scans to identify open ports on the victim.

### S0698 - HermeticWizard

HermeticWizard has the ability to scan ports on a compromised network.

### S0601 - Hildegard

Hildegard has used masscan to look for kubelets in the internal Kubernetes network.

### S0604 - Industroyer

Industroyer uses a custom port scanner to map out a network.

### S0260 - InvisiMole

InvisiMole can scan the network for open ports and vulnerable instances of RDP and SMB protocols.

### S0250 - Koadic

Koadic can scan for open TCP ports on the target network.

### S1185 - LightSpy

To collect data on the host's Wi-Fi connection history, LightSpy reads the `/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist file`.It also utilizes Apple's CWWiFiClient API to scan for nearby Wi-Fi networks and obtain data on the SSID, security type, and RSSI (signal strength) values.

### S0532 - Lucifer

Lucifer can scan for open ports including TCP ports 135 and 1433.

### S0233 - MURKYTOP

MURKYTOP has the capability to scan for open ports on hosts in a connected network.

### S1146 - MgBot

MgBot includes modules for performing HTTP and server service scans.

### S0590 - NBTscan

NBTscan can be used to scan IP networks.

### S0598 - P.A.S. Webshell

P.A.S. Webshell can scan networks for open ports and listening services.

### S0683 - Peirates

Peirates can initiate a port scan against a given IP address.

### S0378 - PoshC2

PoshC2 can perform port scans from an infected host.

### S0192 - Pupy

Pupy has a built-in module for port scanning.

### S0583 - Pysa

Pysa can perform network reconnaissance using the Advanced Port Scanner tool.

### S0458 - Ramsay

Ramsay can scan for systems that are vulnerable to the EternalBlue exploit.

### S0125 - Remsec

Remsec has a plugin that can perform ARP scanning as well as port scanning.

### S1073 - Royal

Royal can scan the network interfaces of targeted systems.

### S0692 - SILENTTRINITY

SILENTTRINITY can scan for open ports on a compromised machine.

### S0374 - SpeakUp

SpeakUp checks for availability of specific ports on servers.

### S0117 - XTunnel

XTunnel is capable of probing the network for open ports.

### S0341 - Xbash

Xbash can perform port scanning of TCP and UDP ports.

### S0412 - ZxShell

ZxShell can launch port scans.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0018 - C0018

During C0018, the threat actors used the SoftPerfect Network Scanner for network scanning.

### C0027 - C0027

During C0027, used RustScan to scan for open ports on targeted ESXi appliances.

### C0004 - CostaRicto

During CostaRicto, the threat actors employed nmap and pscan to scan target environments.

### C0038 - HomeLand Justice

During HomeLand Justice, threat actors executed the Advanced Port Scanner tool on compromised systems.

### C0014 - Operation Wocao

During Operation Wocao, threat actors scanned for open ports and used nbtscan to find NETBIOS nameservers.
