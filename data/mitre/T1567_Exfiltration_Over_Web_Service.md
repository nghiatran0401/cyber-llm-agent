# T1567 - Exfiltration Over Web Service

**Tactic:** Exfiltration
**Platforms:** ESXi, Linux, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1567

## Description

Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel. Popular Web services acting as an exfiltration mechanism may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to compromise. Firewall rules may also already exist to permit traffic to these services.

Web service providers also commonly use SSL/TLS encryption, giving adversaries an added level of protection.

## Detection

### Detection Analytics

**Analytic 1511**

Processes that normally do not initiate network communications suddenly making outbound HTTPS connections with high outbound-to-inbound data ratios. Defender view: correlation between process creation logs (e.g., Word, Excel, PowerShell) and subsequent anomalous network traffic volumes toward common web services (Dropbox, Google Drive, OneDrive).

**Analytic 1512**

Processes (tar, curl, python scripts) accessing large file sets and initiating outbound HTTPS POST requests with payload sizes inconsistent with baseline activity. Defender perspective: detect abnormal sequence of file archival followed by encrypted uploads to external web services.

**Analytic 1513**

Office apps or scripts writing files followed by xattr manipulation (to evade quarantine) and subsequent HTTPS uploads. Defender perspective: anomalous file modification + outbound TLS traffic originating from non-networking apps (Word, Excel, Preview).

**Analytic 1514**

Abnormal API calls from user accounts invoking file upload endpoints outside normal baselines (M365, Google Drive, Box). Defender perspective: monitor unified audit logs for elevated frequency of Upload, Create, or Copy operations from compromised accounts.

**Analytic 1515**

ESXi guest OS or management interface processes establishing unexpected external HTTPS connections. Defender perspective: monitor vmx or hostd processes making outbound web requests with significant data transfer.


## Mitigations

### M1057 - Data Loss Prevention

Data loss prevention can be detect and block sensitive data being uploaded to web services via web browsers.

### M1021 - Restrict Web-Based Content

Web proxies can be used to enforce an external network communication policy that prevents use of unauthorized external services.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0622 - AppleSeed

AppleSeed has exfiltrated files using web services.

### S0547 - DropBook

DropBook has used legitimate web services to exfiltrate data.

### S1179 - Exbyte

Exbyte exfiltrates collected data to online file hosting sites such as `Mega.co.nz`.

### S1245 - InvisibleFerret

InvisibleFerret has leveraged Telegram chat to upload stolen data using the Telegram API with a bot token.

### S1171 - OilCheck

OilCheck can upload documents from compromised hosts to a shared Microsoft Office 365 Outlook email account for exfiltration.

### S1168 - SampleCheck5000

SampleCheck5000 can use the Microsoft Office Exchange Web Services API to access an actor-controlled account and retrieve files for exfiltration.

### S0508 - ngrok

ngrok has been used by threat actors to configure servers for data exfiltration.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0051 - APT28 Nearest Neighbor Campaign

During APT28 Nearest Neighbor Campaign, APT28 exfiltrated data over public-facing webservers – such as Google Drive.

### C0017 - C0017

During C0017, APT41 used Cloudflare services for data exfiltration.

### C0059 - Salesforce Data Exfiltration

During Salesforce Data Exfiltration, threat actors exfiltrated data via legitimate Salesforce API communication channels including the Salesforce Data Loader application.
