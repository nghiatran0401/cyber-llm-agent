# T1008 - Fallback Channels

**Tactic:** Command and Control
**Platforms:** ESXi, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1008

## Description

Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds.

## Detection

### Detection Analytics

**Analytic 1376**

Establishing network connections on uncommon ports or protocols following C2 disruption or blocking. Often executed by processes that typically exhibit no network activity.

**Analytic 1377**

Creation of outbound connections on alternate ports or using covert transport (e.g., ICMP, DNS) from non-network-intensive processes, following known disruption or blocked traffic.

**Analytic 1378**

Outbound fallback traffic from low-profile or background launch agents using unusual protocols or destinations after primary channel inactivity.

**Analytic 1379**

Outbound traffic from host management services or guest-to-host interactions over unusual interfaces (e.g., backdoor API endpoints or external VPN tunnels).


## Mitigations

### M1031 - Network Intrusion Prevention

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific protocol used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0504 - Anchor

Anchor can use secondary C2 servers for communication after establishing connectivity and relaying victim information to primary C2 servers.

### S0622 - AppleSeed

AppleSeed can use a second channel for C2 when the primary channel is in upload mode.

### S0017 - BISCUIT

BISCUIT malware contains a secondary fallback command and control server that is contacted after the primary command and control server.

### S0534 - Bazar

Bazar has the ability to use an alternative C2 server if the primary server fails.

### S0089 - BlackEnergy

BlackEnergy has the capability to communicate over a backup channel via plus.google.com.

### S1039 - Bumblebee

Bumblebee can use backup C2 servers if the primary server fails.

### S0023 - CHOPSTICK

CHOPSTICK can switch to a new C2 channel if the current one is broken.

### S0348 - Cardinal RAT

Cardinal RAT can communicate over multiple C2 host and port combinations.

### S0674 - CharmPower

CharmPower can change its C2 channel once every 360 loops by retrieving a new domain from the actors’ S3 bucket.

### S0538 - Crutch

Crutch has used a hardcoded GitHub repository as a fallback channel.

### S0021 - Derusbi

Derusbi uses a backup communication method with an HTTP beacon.

### S0062 - DustySky

DustySky has two hard-coded domains for C2 servers; if the first does not respond, it will try the second.

### S0377 - Ebury

Ebury has implemented a fallback mechanism to begin using a DGA when the attacker hasn't connected to the infected system for three days.

### S0401 - Exaramel for Linux

Exaramel for Linux can attempt to find a new C2 server if it receives an error.

### S0512 - FatDuke

FatDuke has used several C2 servers per targeted organization.

### S0666 - Gelsemium

Gelsemium can use multiple domains and protocols in C2.

### S0376 - HOPLIGHT

HOPLIGHT has multiple C2 channels in place in case one fails.

### S0260 - InvisiMole

InvisiMole has been configured with several servers available for alternate C2 communications.

### S0044 - JHUHUGIT

JHUHUGIT tests if it can reach its C2 server by first attempting a direct connection, and if it fails, obtaining proxy settings and sending the connection through a proxy, and finally injecting code into a running browser if the proxy method fails.

### S0265 - Kazuar

Kazuar can accept multiple URLs for C2 servers.

### S1020 - Kevin

Kevin can assign hard-coded fallback domains for C2.

### S0236 - Kwampirs

Kwampirs uses a large list of C2 servers that it cycles through until a successful connection is established.

### S0211 - Linfo

Linfo creates a backdoor through which remote attackers can change C2 servers.

### S0409 - Machete

Machete has sent data over HTTP if FTP failed, and has also used a fallback server.

### S0051 - MiniDuke

MiniDuke uses Google Search to identify C2 servers if its primary C2 method via Twitter is not working.

### S0084 - Mis-Type

Mis-Type first attempts to use a Base64-encoded network protocol over a raw TCP socket for C2, and if that method fails, falls back to a secondary HTTP-based protocol to communicate to an alternate C2 server.

### S0699 - Mythic

Mythic can use a list of C2 URLs as fallback mechanisms in case one IP or domain gets blocked.

### S0034 - NETEAGLE

NETEAGLE will attempt to detect if the infected host is configured to a proxy. If so, NETEAGLE will send beacons via an HTTP POST request; otherwise it will send beacons via UDP/6000.

### S1172 - OilBooster

OilBooster can use a backup channel to request a new refresh token from its C2 server after 10 consecutive unsuccessful connections to the primary OneDrive C2 server.

### S0501 - PipeMon

PipeMon can switch to an alternate C2 domain when a particular date has been reached.

### S0269 - QUADAGENT

QUADAGENT uses multiple protocols (HTTPS, HTTP, DNS) for its C2 server as fallback channels if communication with one is unsuccessful.

### S1084 - QUIETEXIT

QUIETEXIT can attempt to connect to a second hard-coded C2 if the first hard-coded C2 address fails.

### S0495 - RDAT

RDAT has used HTTP if DNS C2 communications were not functioning.

### S0629 - RainyDay

RainyDay has the ability to switch between TCP and HTTP for C2 if one method is not working.

### S0085 - S-Type

S-Type primarily uses port 80 for C2, but falls back to ports 443 or 8080 if initial communication fails.

### S1019 - Shark

Shark can update its configuration to use a different C2 server.

### S0444 - ShimRat

ShimRat has used a secondary C2 location if the first was unavailable.

### S0610 - SideTwist

SideTwist has primarily used port 443 for C2 but can use port 80 as a fallback.

### S0058 - SslMM

SslMM has a hard-coded primary and backup C2 string.

### S0603 - Stuxnet

Stuxnet has the ability to generate new C2 domains.

### S0586 - TAINTEDSCRIBE

TAINTEDSCRIBE can randomly pick one of five hard-coded IP addresses for C2 communication; if one of the IP fails, it will wait 60 seconds and then try another IP address.

### S0668 - TinyTurla

TinyTurla can go through a list of C2 server IPs and will try to register with each until one responds.

### S0266 - TrickBot

TrickBot can use secondary C2 servers for communication after establishing connectivity and relaying victim information to primary C2 servers.

### S0022 - Uroburos

Uroburos can use up to 10 channels to communicate between implants.

### S0476 - Valak

Valak can communicate over multiple C2 hosts.

### S0059 - WinMM

WinMM is usually configured with primary and backup domains for C2 communications.

### S0117 - XTunnel

The C2 server used by XTunnel provides a port number to the victim to use as a fallback in case the connection closes on the currently used port.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0002 - Night Dragon

During Night Dragon, threat actors used company extranet servers as secondary C2 servers.
