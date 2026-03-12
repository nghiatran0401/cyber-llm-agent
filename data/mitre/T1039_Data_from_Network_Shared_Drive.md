# T1039 - Data from Network Shared Drive

**Tactic:** Collection
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1039

## Description

Adversaries may search network shares on computers they have compromised to find files of interest. Sensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration. Interactive command shells may be in use, and common functionality within cmd may be used to gather information.

## Detection

### Detection Analytics

**Analytic 1145**

Monitoring of file access to network shares (e.g., C$, Admin$) followed by unusual read or copy operations by processes not typically associated with such activity (e.g., PowerShell, certutil).

**Analytic 1146**

Unusual access or copying of files from mounted network drives (e.g., NFS, CIFS/SMB) by user shells or scripts followed by large data transfer.

**Analytic 1147**

Detection of file access from mounted SMB shares followed by copy or exfil commands from Terminal or script interpreter processes.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0128 - BADNEWS

When it first starts, BADNEWS crawls the victim's mapped drives and collects documents with the following extensions: .doc, .docx, .pdf, .ppt, .pptx, and .txt.

### S0050 - CosmicDuke

CosmicDuke steals user files from network shared drives with file extensions and keywords that match a predefined list.

### S0554 - Egregor

Egregor can collect any files found in the enumerated drivers before sending it to its C2 channel.

### S0458 - Ramsay

Ramsay can collect data from network drives and stage it for exfiltration.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0015 - C0015

During C0015, the threat actors collected files from network shared drives prior to network encryption.
