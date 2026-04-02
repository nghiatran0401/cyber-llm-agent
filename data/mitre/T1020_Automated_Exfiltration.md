# T1020 - Automated Exfiltration

**Tactic:** Exfiltration
**Platforms:** Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1020

## Description

Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection. 

When automated exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as Exfiltration Over C2 Channel and Exfiltration Over Alternative Protocol.

## Detection

### Detection Analytics

**Analytic 1113**

Detection of automated tools or scripts periodically transmitting data to external destinations using scheduled tasks or background processes.

**Analytic 1114**

Background scripts (e.g., via cron) or daemons transmitting data repeatedly to remote IPs or URLs.

**Analytic 1115**

Observation of LaunchAgents or LaunchDaemons establishing periodic external connections indicative of automated data transfer.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0438 - Attor

Attor has a file uploader plugin that automatically exfiltrates the collected data and log files to the C2 server.

### S0050 - CosmicDuke

CosmicDuke exfiltrates collected files automatically over FTP to remote servers.

### S0538 - Crutch

Crutch has automatically exfiltrated stolen files to Dropbox.

### S0600 - Doki

Doki has used a script that gathers information from a hardcoded list of IP addresses and uploads to an Ngrok URL.

### S0377 - Ebury

If credentials are not collected for two weeks, Ebury encrypts the credentials using a public key and sends them via UDP to an IP address located in the DNS TXT record.

### S0363 - Empire

Empire has the ability to automatically send collected data back to the threat actors' C2.

### S1211 - Hannotog

Hannotog can upload encyrpted data for exfiltration.

### S0395 - LightNeuron

LightNeuron can be configured to automatically exfiltrate files under a specified directory.

### S0409 - Machete

Machete’s collected files are exfiltrated automatically to remote servers.

### S1017 - OutSteel

OutSteel can automatically upload collected files to its C2 server.

### S0643 - Peppy

Peppy has the ability to automatically exfiltrate files and keylogs.

### S1148 - Raccoon Stealer

Raccoon Stealer will automatically collect and exfiltrate data identified in received configuration files from command and control nodes.

### S0090 - Rover

Rover automatically searches for files on local drives based on a predefined list of file extensions and sends them to the command and control server every 60 minutes. Rover also automatically sends keylogger files and screenshots to the C2 server on a regular timeframe.

### S0445 - ShimRatReporter

ShimRatReporter sent collected system and network information compiled into a report to an adversary-controlled C2.

### S1166 - Solar

Solar can automatically exfitrate files from compromised systems.

### S1183 - StrelaStealer

StrelaStealer automatically sends gathered email credentials following collection to command and control servers via HTTP POST.

### S0491 - StrongPity

StrongPity can automatically exfiltrate collected documents to the C2 server.

### S0131 - TINYTYPHON

When a document is found matching one of the extensions in the configuration, TINYTYPHON uploads it to the C2 server.

### S0467 - TajMahal

TajMahal has the ability to manage an automated queue of egress files and commands sent to its C2.

### S0136 - USBStealer

USBStealer automatically exfiltrates collected files via removable media when an infected device connects to an air-gapped victim machine after initially being connected to an internet-enabled victim machine.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0046 - ArcaneDoor

ArcaneDoor included scripted exfiltration of collected data.

### C0001 - Frankenstein

During Frankenstein, the threat actors collected information via Empire, which was automatically sent back to the adversary's C2.

### C0059 - Salesforce Data Exfiltration

During Salesforce Data Exfiltration, threat actors used API queries to automatically exfiltrate large volumes of data.
