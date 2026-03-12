# T1665 - Hide Infrastructure

**Tactic:** Command and Control
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1665

## Description

Adversaries may manipulate network traffic in order to hide and evade detection of their C2 infrastructure. This can be accomplished by identifying and filtering traffic from defensive tools, masking malicious domains to obfuscate the true destination from both automated scanning tools and security researchers, and otherwise hiding malicious artifacts to delay discovery and prolong the effectiveness of adversary infrastructure that could otherwise be identified, blocked, or taken down entirely.

C2 networks may include the use of Proxy or VPNs to disguise IP addresses, which can allow adversaries to blend in with normal network traffic and bypass conditional access policies or anti-abuse protections. For example, an adversary may use a virtual private cloud to spoof their IP address to closer align with a victim's IP address ranges. This may also bypass security measures relying on geolocation of the source IP address.

Adversaries may also attempt to filter network traffic in order to evade defensive tools in numerous ways, including blocking/redirecting common incident responder or security appliance user agents. Filtering traffic based on IP and geo-fencing may also avoid automated sandboxing or researcher activity (i.e., Virtualization/Sandbox Evasion).

Hiding C2 infrastructure may also be supported by Resource Development activities such as Acquire Infrastructure and Compromise Infrastructure. For example, using widely trusted hosting services or domains such as prominent URL shortening providers or marketing services for C2 networks may enable adversaries to present benign content that later redirects victims to malicious web pages or infrastructure once specific conditions are met.

## Detection

### Detection Analytics

**Analytic 1148**

Monitor DNS queries, proxy logs, and user-agent strings for anomalous patterns associated with adversary attempts to hide infrastructure. Defenders may observe DNS resolutions to short-lived domains, abnormal WHOIS registration data, or filtering of known defensive/responder IP addresses.

**Analytic 1149**

Detect adversaries filtering traffic or modifying server responses to evade scanning. Monitor iptables, nftables, or proxy configurations that deny or redirect requests from known scanning agents or defensive tools.

**Analytic 1150**

Monitor unified logs for manipulation of proxy configurations, DNS resolution, or filtering rules. Adversaries may redirect responses or use trusted domains that later resolve to malicious C2 infrastructure.

**Analytic 1151**

Inspect network telemetry for adversary attempts to blend malicious traffic with legitimate flows using VPNs, proxies, or geolocation spoofing. Defensive teams may observe anomalous tunnels, encrypted sessions to suspicious domains, or geo-mismatched IP activity.

**Analytic 1152**

Monitor VM-level DNS and network traffic logs for adversary-controlled domains or selective response behavior (e.g., dropped requests from security scanners).


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1111 - DarkGate

DarkGate command and control includes hard-coded domains in the malware masquerading as legitimate services such as Akamai CDN or Amazon Web Services.

### S1206 - JumbledPath

JumbledPath can use a chain of jump hosts to communicate with compromised devices to obscure actor infrastructure.

### S1164 - UPSTYLE

UPSTYLE attempts to retrieve a non-existent webpage from the command and control server resulting in hidden commands sent via resulting error messages.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0055 - Quad7 Activity

Quad7 Activity has rotated the compromised SOHO IPs used in password spraying activity to hamper detection and network blocking activities by defenders.

### C0024 - SolarWinds Compromise

During the SolarWinds Compromise, APT29 set the hostnames of their C2 infrastructure to match legitimate hostnames in the victim environment. They also used IP addresses originating from the same country as the victim for their VPN infrastructure.
