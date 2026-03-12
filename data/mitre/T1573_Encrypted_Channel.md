# T1573 - Encrypted Channel

**Tactic:** Command and Control
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1573

## Description

Adversaries may employ an encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if secret keys are encoded and/or generated within malware samples/configuration files.

## Detection

### Detection Analytics

**Analytic 0759**

Processes that normally do not initiate network connections establishing outbound encrypted TLS/SSL sessions, especially with asymmetric traffic volumes (client sending more than receiving) or non-standard certificate chains. Defender observations correlate process creation with unexpected network encryption libraries being loaded.

**Analytic 0760**

Processes like curl, wget, python, socat, or custom binaries initiating TLS/SSL sessions to non-standard destinations. Defender sees abnormal syscalls for connect(), loading of libssl libraries, and persistent outbound encrypted traffic from daemons not normally communicating externally.

**Analytic 0761**

Applications or launchd jobs initiating encrypted TLS traffic to rare external hosts. Defender observes unified logs showing ssl/TLS API calls by processes not baseline-approved, and payload entropy suggesting encrypted C2 sessions.

**Analytic 0762**

VMware management daemons or guest processes initiating encrypted connections outside expected vCenter, update servers, or internal comms. Defender identifies hostd or vpxa initiating outbound TLS flows with uncommon destinations.

**Analytic 0763**

Unusual TLS tunnels through ports not normally encrypted (e.g., TLS on port 8080, 53). Defender sees NetFlow/IPFIX or packet inspection indicating high-entropy traffic volumes and asymmetric client/server exchange ratios.


## Mitigations

### M1031 - Network Intrusion Prevention

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.

### M1020 - SSL/TLS Inspection

SSL/TLS inspection can be used to see the contents of encrypted sessions to look for network-based indicators of malware communication protocols.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0631 - Chaes

Chaes has used encryption for its C2 channel.

### S0498 - Cryptoistic

Cryptoistic can engage in encrypted communications with C2.

### S0367 - Emotet

Emotet has encrypted data before sending to the C2 server.

### S1198 - Gomir

Gomir uses a custom encryption algorithm for content sent to command and control infrastructure.

### S0681 - Lizar

Lizar can support encrypted communications between the client and server.

### S1016 - MacMa

MacMa has used TLS encryption to initialize a custom protocol for C2 communications.

### S0198 - NETWIRE

NETWIRE can encrypt C2 communications.

### S1046 - PowGoop

PowGoop can receive encrypted commands from C2.

### S1012 - PowerLess

PowerLess can use an encrypted channel for C2 communications.

### S0662 - RCSession

RCSession can use an encrypted beacon to check in with C2.

### S0032 - gh0st RAT

gh0st RAT has encrypted TCP communications to evade detection.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0035 - KV Botnet Activity

KV Botnet Activity command and control activity includes transmission of an RSA public key in communication from the server, but this is followed by subsequent negotiation stages that represent a form of handshake similar to TLS negotiation.

### C0030 - Triton Safety Instrumented System Attack

In the Triton Safety Instrumented System Attack, TEMP.Veles used cryptcat binaries to encrypt their traffic.
