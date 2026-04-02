# T1001 - Data Obfuscation

**Tactic:** Command and Control
**Platforms:** ESXi, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1001

## Description

Adversaries may obfuscate command and control traffic to make it more difficult to detect. Command and control (C2) communications are hidden (but not necessarily encrypted) in an attempt to make the content more difficult to discover or decipher and to make the communication less conspicuous and hide commands from being seen. This encompasses many methods, such as adding junk data to protocol traffic, using steganography, or impersonating legitimate protocols.

## Detection

### Detection Analytics

**Analytic 0144**

Detects excessive outbound traffic to remote host over HTTP(S) from uncommon or previously unseen processes.

**Analytic 0145**

Identifies custom or previously unseen userland processes initiating high-volume HTTP connections with low response volume.

**Analytic 0146**

Flags unexpected user applications initiating long-lived HTTP(S) sessions with irregular traffic patterns.


## Mitigations

### M1031 - Network Intrusion Prevention

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate some obfuscation activity at the network level.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1111 - DarkGate

DarkGate will retrieved encrypted commands from its command and control server for follow-on actions such as cryptocurrency mining.

### S1120 - FRAMESTING

FRAMESTING can send and receive zlib compressed data within `POST` requests.

### S0381 - FlawedAmmyy

FlawedAmmyy may obfuscate portions of the initial C2 handshake.

### S1044 - FunnyDream

FunnyDream can send compressed and obfuscated packets to C2.

### S1100 - Ninja

Ninja has the ability to modify headers and URL paths to hide malicious traffic in HTTP requests.

### S0439 - Okrum

Okrum leverages the HTTP protocol for C2 communication, while hiding the actual messages in the Cookie and Set-Cookie headers of the HTTP requests.

### S0495 - RDAT

RDAT has used encoded data within subdomains as AES ciphertext to communicate from the host to the C2.

### S0533 - SLOTHFULMEDIA

SLOTHFULMEDIA has hashed a string containing system information prior to exfiltration via POST requests.

### S0610 - SideTwist

SideTwist can embed C2 responses in the source code of a fake Flickr webpage.

### S1183 - StrelaStealer

StrelaStealer encrypts the payload of HTTP POST communications using the same XOR key used for the malware's DLL payload.

### S0682 - TrailBlazer

TrailBlazer can masquerade its C2 traffic as legitimate Google Notifications HTTP requests.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0014 - Operation Wocao

During Operation Wocao, threat actors encrypted IP addresses used for "Agent" proxy hops with RC4.
