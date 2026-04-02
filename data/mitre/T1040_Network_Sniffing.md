# T1040 - Network Sniffing

**Tactic:** Credential Access, Discovery
**Platforms:** IaaS, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1040

## Description

Adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.

Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as LLMNR/NBT-NS Poisoning and SMB Relay, can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary.

Network sniffing may reveal configuration details, such as running services, version numbers, and other network characteristics (e.g. IP addresses, hostnames, VLAN IDs) necessary for subsequent Lateral Movement and/or Defense Evasion activities. Adversaries may likely also utilize network sniffing during Adversary-in-the-Middle (AiTM) to passively gain additional knowledge about the environment.

In cloud-based environments, adversaries may still be able to use traffic mirroring services to sniff network traffic from virtual machines. For example, AWS Traffic Mirroring, GCP Packet Mirroring, and Azure vTap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to. Often, much of this traffic will be in cleartext due to the use of TLS termination at the load balancer level to reduce the strain of encrypting and decrypting traffic. The adversary can then use exfiltration techniques such as Transfer Data to Cloud Account in order to access the sniffed traffic.

On network devices, adversaries may perform network captures using Network Device CLI commands such as `monitor capture`.

## Detection

### Detection Analytics

**Analytic 0875**

Detects suspicious execution of network monitoring tools (e.g., Wireshark, tshark, Microsoft Message Analyzer), driver loading indicative of promiscuous mode, or non-admin user privilege escalation to access NICs for capture.

**Analytic 0876**

Correlates interface mode changes to promiscuous with execution of sniffing tools like tcpdump, tshark, or custom pcap libraries. Detects abnormal NIC configurations and unauthorized sniffing from non-root sessions.

**Analytic 0877**

Detects enabling of interface sniffing via packet capture tools or AppleScript triggering `tcpdump`. Leverages Unified Logs and process lineage to identify suspicious use of `pfctl`, `tcpdump`, or `libpcap` libraries.

**Analytic 0878**

Detects creation of traffic mirroring sessions (e.g., AWS VPC Traffic Mirroring, Azure vTAP) that redirect traffic from critical assets to other virtual instances, often followed by file creation or session establishment.

**Analytic 0879**

Detects execution of capture commands via CLI (`monitor capture`, `debug packet`, etc.) or unauthorized CLI access followed by logging configuration changes on Cisco/Juniper/Arista gear.


## Mitigations

### M1041 - Encrypt Sensitive Information

Ensure that all wired and/or wireless traffic is encrypted appropriately. Use best practices for authentication protocols, such as Kerberos, and ensure web traffic that may contain credentials is protected by SSL/TLS.

### M1032 - Multi-factor Authentication

Use multi-factor authentication wherever possible.

### M1030 - Network Segmentation

Deny direct access of broadcasts and multicast sniffing, and prevent attacks such as LLMNR/NBT-NS Poisoning and SMB Relay

### M1018 - User Account Management

In cloud environments, ensure that users are not granted permissions to create or modify traffic mirrors unless this is explicitly required.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1224 - CASTLETAP

CASTLETAP has the ability to create a raw promiscuous socket to sniff network traffic.

### S0367 - Emotet

Emotet has been observed to hook network APIs to monitor network traffic.

### S0363 - Empire

Empire can be used to conduct packet captures on target hosts.

### S0661 - FoggyWeb

FoggyWeb can configure custom listeners to passively monitor all incoming HTTP GET and POST requests sent to the AD FS server from the intranet/internet and intercept HTTP requests that match the custom URI patterns defined by the actor.

### S0357 - Impacket

Impacket can be used to sniff network traffic via an interface or raw socket.

### S1203 - J-magic

J-magic has a pcap listener function that can create an Extended Berkley Packet Filter (eBPF) on designated interfaces and ports.

### S1206 - JumbledPath

JumbledPath has the ability to perform packet capture on remote devices via actor-defined jump-hosts.

### S1186 - Line Dancer

Line Dancer can create and exfiltrate packet captures from compromised environments.

### S0443 - MESSAGETAP

MESSAGETAP uses the libpcap library to listen to all traffic and parses network protocols starting with Ethernet and IP layers. It continues parsing protocol layers including SCTP, SCCP, and TCAP and finally extracts SMS message data and routing metadata.

### S0590 - NBTscan

NBTscan can dump and print whole packet content.

### S0587 - Penquin

Penquin can sniff network traffic to look for packets matching specific conditions.

### S0378 - PoshC2

PoshC2 contains a module for taking packet captures on compromised hosts.

### S0019 - Regin

Regin appears to have functionality to sniff for credentials passed over HTTP, SMTP, and SMB.

### S0174 - Responder

Responder captures hashes and credentials that are sent to the system after the name services have been poisoned.

### S1154 - VersaMem

VersaMem hooked the Catalina application filter chain `doFilter` on compromised systems to monitor all inbound requests to the local Tomcat web server, inspecting them for parameters like passwords and follow-on Java modules.

### S1204 - cd00r

cd00r can use the libpcap library to monitor captured packets for specifc sequences.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0028 - 2015 Ukraine Electric Power Attack

During the 2015 Ukraine Electric Power Attack, Sandworm Team used BlackEnergy’s network sniffer module to discover user credentials being sent over the network between the local LAN and the power grid’s industrial control systems.

### C0046 - ArcaneDoor

ArcaneDoor included network packet capture and sniffing for data collection in victim environments.

### C0056 - RedPenguin

During RedPenguin, UNC3886 used a passive backdoor to act as a libpcap-based packet sniffer.
