# T1132 - Data Encoding

**Tactic:** Command and Control
**Platforms:** ESXi, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1132

## Description

Adversaries may encode data to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system. Use of data encoding may adhere to existing protocol specifications and includes use of ASCII, Unicode, Base64, MIME, or other binary-to-text and character encoding systems. Some data encoding systems may also result in data compression, such as gzip.

## Detection

### Detection Analytics

**Analytic 0302**

Atypical processes (e.g., powershell.exe, regsvr32.exe) encode large outbound traffic using Base64 or other character encodings; this traffic is sent over uncommon ports or embedded in protocol fields (e.g., HTTP cookies or headers).

**Analytic 0303**

Custom scripts or processes encode outbound traffic using gzip, Base64, or hex prior to exfiltration via curl, wget, or custom sockets. Encoding typically occurs before or during outbound connections from non-network daemons.

**Analytic 0304**

Processes use built-in encoding utilities (e.g., `base64`, `xxd`, or `plutil`) to encode file contents followed by HTTP/HTTPS transfer via curl or custom applications.

**Analytic 0305**

ESXi daemons (e.g., hostd, vpxa) are wrapped or impersonated to send large outbound traffic using gzip/Base64 encoding over SSH or HTTP. These actions follow suspicious logins or shell access.


## Mitigations

### M1031 - Network Intrusion Prevention

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0128 - BADNEWS

After encrypting C2 data, BADNEWS converts it into a hexadecimal representation and then encodes it into base64.

### S0132 - H1N1

H1N1 obfuscates C2 traffic with an altered version of base64.

### S0362 - Linux Rabbit

Linux Rabbit sends the payload from the C2 server as an encoded URL parameter.

### S0699 - Mythic

Mythic provides various transform functions to encode and/or randomize C2 data.

### S0386 - Ursnif

Ursnif has used encoded data in HTTP URLs for C2.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
