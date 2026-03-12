# T1030 - Data Transfer Size Limits

**Tactic:** Exfiltration
**Platforms:** ESXi, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1030

## Description

An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts.

## Detection

### Detection Analytics

**Analytic 0596**

Adversary uses a process to establish outbound connections that transmit uniform packet sizes at a consistent interval, avoiding threshold-based network alerts.

**Analytic 0597**

Outbound connections from non-network-facing processes repeatedly send similarly sized payloads within uniform time intervals.

**Analytic 0598**

Processes on macOS initiate external connections that consistently transmit data in fixed sizes using LaunchAgents or unexpected users.


## Mitigations

### M1031 - Network Intrusion Prevention

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary command and control infrastructure and malware can be used to mitigate activity at the network level.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0622 - AppleSeed

AppleSeed has divided files if the size is 0x1000000 bytes or more.

### S0030 - Carbanak

Carbanak exfiltrates data in compressed chunks if a message is larger than 4096 bytes .

### S0154 - Cobalt Strike

Cobalt Strike will break large data sets into smaller chunks for exfiltration.

### S0170 - Helminth

Helminth splits data into chunks up to 23 bytes and sends the data in DNS queries to its C2 server.

### S0487 - Kessel

Kessel can split the data to be exilftrated into chunks that will fit in subdomains of DNS queries.

### S1020 - Kevin

Kevin can exfiltrate data to the C2 server in 27-character chunks.

### S1141 - LunarWeb

LunarWeb can split exfiltrated data that exceeds 1.33 MB in size into multiple random sized parts between 384 and 512 KB.

### S0699 - Mythic

Mythic supports custom chunk sizes used to upload/download files.

### S0644 - ObliqueRAT

ObliqueRAT can break large files of interest into smaller chunks to prepare them for exfiltration.

### S0264 - OopsIE

OopsIE exfiltrates command output and collected files to its C2 server in 1500-byte blocks.

### S0150 - POSHSPY

POSHSPY uploads data in 2048-byte chunks.

### S0495 - RDAT

RDAT can upload a file via HTTP POST response to the C2 split into 102,400-byte portions. RDAT can also download data from the C2 which is split into 81,920-byte portions.

### S1040 - Rclone

The Rclone "chunker" overlay supports splitting large files in smaller chunks during upload to circumvent size limits.

### S1200 - StealBit

StealBit can be configured to exfiltrate files at a specified rate to evade network detection mechanisms.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0015 - C0015

During C0015, the threat actors limited Rclone's bandwidth setting during exfiltration.

### C0026 - C0026

During C0026, the threat actors split encrypted archives containing stolen files and information into 3MB parts prior to exfiltration.
