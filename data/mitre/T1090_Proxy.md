# T1090 - Proxy

**Tactic:** Command and Control
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1090

## Description

Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including HTRAN, ZXProxy, and ZXPortMap. Adversaries use these types of proxies to manage command and control communications, reduce the number of simultaneous outbound network connections, provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between victims to avoid suspicion. Adversaries may chain together multiple proxies to further disguise the source of malicious traffic.

Adversaries can also take advantage of routing schemes in Content Delivery Networks (CDNs) to proxy command and control traffic.

## Detection

### Detection Analytics

**Analytic 1229**

Suspicious process spawning (e.g., `rundll32`, `svchost`, `powershell`, or `netsh`) followed by network connection creation to internal hosts or uncommon external endpoints on high or non-standard ports.

**Analytic 1230**

User-space tools (e.g., `socat`, `ncat`, `iptables`, `ssh`) used in non-standard ways to establish reverse shells, port-forwarding, or inter-host connections. Often chained with uncommon outbound destinations or SSH tunnels.

**Analytic 1231**

AppleScript, LaunchAgents, or remote login services (`ssh`, `networksetup`) establishing proxy tunnels or dynamic port forwards to external IPs or alternate local hosts.

**Analytic 1232**

Direct use of `nc`, `socat`, or reverse tunnel scripts initiated by abnormal user contexts or unauthorized VIBs initiating connections from hypervisor to external systems.

**Analytic 1233**

Dynamic or static port forwarding rules added to route traffic through an internal host, or configuration changes to proxy firewall rules not aligned with baselined policy.


## Mitigations

### M1037 - Filter Network Traffic

Traffic to known anonymity networks and C2 infrastructure can be blocked through the use of network allow and block lists. It should be noted that this kind of blocking may be circumvented by other techniques like Domain Fronting.

### M1031 - Network Intrusion Prevention

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific C2 protocol used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools.

### M1020 - SSL/TLS Inspection

If it is possible to inspect HTTPS traffic, the captures can be analyzed for connections that appear to be domain fronting.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0456 - Aria-body

Aria-body has the ability to use a reverse SOCKS proxy module.

### S0347 - AuditCred

AuditCred can utilize proxy for communications.

### S0245 - BADCALL

BADCALL functions as a proxy server between the victim and C2 server.

### S1081 - BADHATCH

BADHATCH can use SOCKS4 and SOCKS5 proxies to connect to actor-controlled C2 servers. BADHATCH can also emulate a reverse proxy on a compromised machine to connect with actor-controlled C2 servers.

### S0268 - Bisonal

Bisonal has supported use of a proxy server.

### S0348 - Cardinal RAT

Cardinal RAT can act as a reverse proxy.

### S0384 - Dridex

Dridex contains a backconnect module for tunneling network traffic through a victim's computer. Infected computers become part of a P2P botnet that can relay C2 traffic to other infected peers.

### S1144 - FRP

FRP can proxy communications through a server in public IP space to local servers located behind a NAT or firewall.

### S1044 - FunnyDream

FunnyDream can identify and use configured proxies in a compromised network for C2 communication.

### S1197 - GoBear

GoBear implements SOCKS5 proxy functionality.

### S0690 - Green Lambert

Green Lambert can use proxies for C2 traffic.

### S0246 - HARDRAIN

HARDRAIN uses the command <code>cmd.exe /c netsh firewall add portopening TCP 443 "adp"</code> and makes the victim machine function as a proxy server.

### S0376 - HOPLIGHT

HOPLIGHT has multiple proxy options that mask traffic between the malware and the remote operators.

### S0040 - HTRAN

HTRAN can proxy TCP socket connections to obfuscate command and control infrastructure.

### S1229 - Havoc

Havoc has the ability to route HTTP/S communications through designated proxies.

### S1051 - KEYPLUG

KEYPLUG has used Cloudflare CDN associated infrastructure to redirect C2 communications to malicious domains.

### S0669 - KOCTOPUS

KOCTOPUS has deployed a modified version of Invoke-Ngrok to expose open local ports to the Internet.

### S1190 - Kapeka

Kapeka can identify system proxy settings via `WinHttpGetIEProxyConfigForCurrentUser()` during initialization and utilize these settings for subsequent command and control operations.

### S0487 - Kessel

Kessel can use a proxy during exfiltration if set in the configuration.

### S1121 - LITTLELAMB.WOOLTEA

LITTLELAMB.WOOLTEA has the ability to function as a SOCKS proxy.

### S1141 - LunarWeb

LunarWeb has the ability to use a HTTP proxy server for C&C communications.

### S0198 - NETWIRE

NETWIRE can implement use of proxies to pivot traffic.

### S1189 - Neo-reGeorg

Neo-reGeorg has the ability to establish a SOCKS5 proxy on a compromised web server.

### S0435 - PLEAD

PLEAD has the ability to proxy network communications.

### S0378 - PoshC2

PoshC2 contains modules that allow for use of proxies in command and control.

### S0262 - QuasarRAT

QuasarRAT can communicate over a reverse proxy using SOCKS5.

### S0629 - RainyDay

RainyDay can use proxy tools including boost_proxy_client for reverse proxy functionality.

### S1212 - RansomHub

RansomHub can use a proxy to connect to remote SFTP servers.

### S0332 - Remcos

Remcos uses the infected hosts as SOCKS5 proxies to allow for tunneling and proxying.

### S0461 - SDBbot

SDBbot has the ability to use port forwarding to establish a proxy between a target host and C2.

### S1210 - Sagerunex

Sagerunex uses several proxy configuration settings to ensure connectivity.

### S1099 - Samurai

Samurai has the ability to proxy connections to specified remote IPs and ports through a a proxy module.

### S0273 - Socksbot

Socksbot can start SOCKS proxy threads.

### S0615 - SombRAT

SombRAT has the ability to use an embedded SOCKS proxy in C2 communications.

### S0436 - TSCookie

TSCookie has the ability to proxy communications with command and control (C2) servers.

### S0263 - TYPEFRAME

A TYPEFRAME variant can force the compromised system to function as a proxy server.

### S0386 - Ursnif

Ursnif has used a peer-to-peer (P2P) network for C2.

### S0207 - Vasport

Vasport is capable of tunneling though a proxy.

### S0670 - WarzoneRAT

WarzoneRAT has the capability to act as a reverse proxy.

### S0117 - XTunnel

XTunnel relays traffic between a C2 server and a victim.

### S1114 - ZIPLINE

ZIPLINE can create a proxy server on compromised hosts.

### S0412 - ZxShell

ZxShell can set up an HTTP or SOCKS proxy.

### S0283 - jRAT

jRAT can serve as a SOCKS proxy server.

### S0108 - netsh

netsh can be used to set up a proxy tunnel to allow remote host access to an infected host.

### S0508 - ngrok

ngrok can be used to proxy connections to machines located behind NAT or firewalls.

### S1187 - reGeorg

reGeorg can establish an HTTP or SOCKS proxy to tunnel data in and out of a network.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0017 - C0017

During C0017, APT41 used the Cloudflare CDN to proxy C2 traffic.

### C0027 - C0027

During C0027, Scattered Spider installed the open-source rsocx reverse proxy tool on a targeted ESXi appliance.

### C0048 - Operation MidnightEclipse

During Operation MidnightEclipse, threat actors used the GO Simple Tunnel reverse proxy tool.

### C0013 - Operation Sharpshooter

For Operation Sharpshooter, the threat actors used the ExpressVPN service to hide their location.

### C0014 - Operation Wocao

During Operation Wocao, threat actors used a custom proxy tool called "Agent" which has support for multiple hops.

### C0047 - RedDelta Modified PlugX Infection Chain Operations

Mustang Panda proxied communication through the Cloudflare CDN service during RedDelta Modified PlugX Infection Chain Operations.

### C0056 - RedPenguin

During RedPenguin, UNC3886 used malware capable of establishing a SOCKS proxy connection to a specified IP and port.

### C0059 - Salesforce Data Exfiltration

During Salesforce Data Exfiltration, threat actors used Mullvad VPN IPs to proxy voice phishing calls.

### C0058 - SharePoint ToolShell Exploitation

During SharePoint ToolShell Exploitation, threat actors used Fast Reverse Proxy to communicate with C2.
