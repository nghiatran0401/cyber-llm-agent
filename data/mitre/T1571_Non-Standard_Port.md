# T1571 - Non-Standard Port

**Tactic:** Command and Control
**Platforms:** ESXi, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1571

## Description

Adversaries may communicate using a protocol and port pairing that are typically not associated. For example, HTTPS over port 8088 or port 587 as opposed to the traditional port 443. Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data.

Adversaries may also make changes to victim systems to abuse non-standard ports. For example, Registry keys and other configuration settings can be used to modify protocol and port pairings.

## Detection

### Detection Analytics

**Analytic 0633**

Processes initiating outbound connections on uncommon ports or using protocols inconsistent with the assigned port. Correlating process creation with subsequent network connections reveals anomalies such as svchost.exe or Office applications using high, atypical ports.

**Analytic 0634**

Unusual daemons or user processes binding/listening on ports outside of standard ranges, or initiating client connections using mismatched protocol/port pairings.

**Analytic 0635**

Applications making outbound connections on non-standard ports or launchd services bound to ports inconsistent with system baselines.

**Analytic 0636**

VM services or management daemons communicating on ports not defined by VMware defaults, such as vpxa or hostd processes initiating traffic over high-numbered or unexpected ports.


## Mitigations

### M1031 - Network Intrusion Prevention

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.

### M1030 - Network Segmentation

Properly configure firewalls and proxies to limit outgoing traffic to only necessary ports for that particular network segment.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0245 - BADCALL

BADCALL communicates on ports 443 and 8000 with a FakeTLS method.

### S0239 - Bankshot

Bankshot binds and listens on port 1058 for HTTP traffic while also utilizing a FakeTLS method.

### S1246 - BeaverTail

BeaverTail has communicated with C2 IP addresses over ports 1224 or 1244.

### S0574 - BendyBear

BendyBear has used a custom RC4 and XOR encrypted protocol over port 443 for C2.

### S1155 - Covenant

Covenant listeners and controllers can be configured to use non-standard ports.

### S0687 - Cyclops Blink

Cyclops Blink can use non-standard ports for C2 not typically associated with HTTP or HTTPS traffic.

### S0021 - Derusbi

Derusbi has used unencrypted HTTP on port 443 for C2.

### S0367 - Emotet

Emotet has used HTTP over ports such as 20, 22, 443, 7080, and 50000, in addition to using ports commonly associated with HTTP/S.

### S0493 - GoldenSpy

GoldenSpy has used HTTP over ports 9005 and 9006 for network traffic, 9002 for C2 requests, 33666 as a WebSocket, and 8090 to download files.

### S0237 - GravityRAT

GravityRAT has used HTTP over a non-standard port, such as TCP port 46769.

### S0246 - HARDRAIN

HARDRAIN binds and listens on port 443 with a FakeTLS method.

### S0376 - HOPLIGHT

HOPLIGHT has connected outbound over TCP port 443 with a FakeTLS method.

### S1211 - Hannotog

Hannotog uses non-standard listening ports, such as UDP 5900, for command and control purposes.

### S1245 - InvisibleFerret

InvisibleFerret has been observed utilizing HTTP communications to the C2 server over ports 1224, 2245 and 8637.

### S1016 - MacMa

MacMa has used TCP port 5633 for C2 Communication.

### S0455 - Metamorfo

Metamorfo has communicated with hosts over raw TCP on port 9999.

### S0149 - MoonWind

MoonWind communicates over ports 80, 443, 53, and 8080 via raw sockets instead of the protocols usually associated with the ports.

### S0352 - OSX_OCEANLOTUS.D

OSX_OCEANLOTUS.D has used a custom binary protocol over TCP port 443 for C2.

### S1145 - Pikabot

Pikabot uses non-standard ports, such as 2967, 2223, and others, for HTTPS command and control communication.

### S1031 - PingPull

PingPull can use HTTPS over port 8080 for C2.

### S0013 - PlugX

PlugX has used random, high-number, non-standard ports to listen for subsequent actions and C2 activities.

### S0428 - PoetRAT

PoetRAT used TLS to encrypt communications over port 143

### S0262 - QuasarRAT

QuasarRAT can use port 4782 on the compromised host for TCP callbacks.

### S0148 - RTM

RTM used Port 44443 for its VNC module.

### S1130 - Raspberry Robin

Raspberry Robin will communicate via HTTP over port 8080 for command and control traffic.

### S0153 - RedLeaves

RedLeaves can use HTTP over non-standard ports, such as 995, for C2.

### S1078 - RotaJakiro

RotaJakiro uses a custom binary protocol over TCP port 443.

### S1049 - SUGARUSH

SUGARUSH has used port 4585 for a TCP connection to its C2.

### S1085 - Sardonic

Sardonic has the ability to connect with actor-controlled C2 servers using a custom binary protocol over port 443.

### S0491 - StrongPity

StrongPity has used HTTPS over port 1402 in C2 communication.

### S0263 - TYPEFRAME

TYPEFRAME has used ports 443, 8080, and 8443 with a FakeTLS method.

### S0266 - TrickBot

Some TrickBot samples have used HTTP over ports 447 and 8082 for C2. Newer versions of TrickBot have been known to use a custom communication protocol which sends the data unencrypted over port 443.

### S1218 - VIRTUALPIE

VIRTUALPIE has created listeners on hard coded TCP port 546.

### S1217 - VIRTUALPITA

VIRTUALPITA has created listeners on hard coded TCP ports such as 2233, 7475, and 18098.

### S0515 - WellMail

WellMail has been observed using TCP port 25, without using SMTP, to leverage an open port for secure command and control communications.

### S0412 - ZxShell

ZxShell can use ports 1985 and 1986 in HTTP/S communication.

### S0385 - njRAT

njRAT has used port 1177 for HTTP C2 communications.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0018 - C0018

During C0018, the threat actors opened a variety of ports, including ports 28035, 32467, 41578, and 46892, to establish RDP connections.

### C0032 - C0032

During the C0032 campaign, TEMP.Veles used port-protocol mismatches on ports such as 443, 4444, 8531, and 50501 during C2.

### C0043 - Indian Critical Infrastructure Intrusions

During Indian Critical Infrastructure Intrusions, RedEcho used non-standard ports such as TCP 8080 for HTTP communication.

### C0035 - KV Botnet Activity

KV Botnet Activity generates a random port number greater than 30,000 to serve as the listener for subsequent command and control activity.

### C0014 - Operation Wocao

During Operation Wocao, the threat actors used uncommon high ports for its backdoor C2, including ports 25667 and 47000.

### C0055 - Quad7 Activity

Quad7 Activity has used non-standard TCP ports – such as 7777, 11288, 63256, 63210, 3256, and 3556 for C2.

### C0056 - RedPenguin

During RedPenguin, UNC3886 used a backdoor that binds to port 45678 by default.
