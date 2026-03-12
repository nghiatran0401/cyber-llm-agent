# T1102 - Web Service

**Tactic:** Command and Control
**Platforms:** ESXi, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1102

## Description

Adversaries may use an existing, legitimate external Web service as a means for relaying data to/from a compromised system. Popular websites, cloud services, and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google, Microsoft, or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection.

Use of Web services may also protect back-end C2 infrastructure from discovery through malware binary analysis while also enabling operational resiliency (since this infrastructure may be dynamically changed).

## Detection

### Detection Analytics

**Analytic 1189**

Detects unusual outbound connections to web services from uncommon processes using SSL/TLS, particularly those exhibiting high outbound data volume or persistence.

**Analytic 1190**

Detects command-line tools, agents, or scripts making outbound HTTPS connections to popular web services like Discord, Slack, Dropbox, or Graph API in an unusual context.

**Analytic 1191**

Detects user agents or background services making unauthorized or unscheduled web API calls to cloud/web services over HTTPS.

**Analytic 1192**

Detects guest VMs or management agents issuing HTTP(S) traffic to external services without a valid patch management or backup justification.


## Mitigations

### M1031 - Network Intrusion Prevention

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.

### M1021 - Restrict Web-Based Content

Web proxies can be used to enforce external network communication policy that prevents use of unauthorized external services.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1081 - BADHATCH

BADHATCH can be utilized to abuse `sslip.io`, a free IP to domain mapping service, as part of actor-controlled C2 channels.

### S0534 - Bazar

Bazar downloads have been hosted on Google Docs.

### S0635 - BoomBox

BoomBox can download files from Dropbox using a hardcoded access token.

### S1063 - Brute Ratel C4

Brute Ratel C4 can use legitimate websites for external C2 channels including Slack, Discord, and MS Teams.

### S1039 - Bumblebee

Bumblebee has been downloaded to victim's machines from OneDrive.

### S1149 - CHIMNEYSWEEP

CHIMNEYSWEEP has the ability to use use Telegram channels to return a list of commands to be executed, to download additional payloads, or to create a reverse shell.

### S0335 - Carbon

Carbon can use Pastebin to receive C2 commands.

### S0674 - CharmPower

CharmPower can download additional modules from actor-controlled Amazon S3 buckets.

### S1066 - DarkTortilla

DarkTortilla can retrieve its primary payload from public sites such as Pastebin and Textbin.

### S0600 - Doki

Doki has used the dogechain.info API to generate a C2 address.

### S0547 - DropBook

DropBook can communicate with its operators by exploiting the Simplenote, DropBox, and the social media platform, Facebook, where it can create fake accounts to control the backdoor and receive instructions.

### S0561 - GuLoader

GuLoader has the ability to download malware from Google Drive.

### S0601 - Hildegard

Hildegard has downloaded scripts from GitHub.

### S1160 - Latrodectus

Latrodectus has used Google Firebase to download malicious installation scripts.

### S1221 - MOPSLED

MOPSLED can use third-party web services such as GitHub and Google Drive for C2.

### S0198 - NETWIRE

NETWIRE has used web services including Paste.ee to host payloads.

### S1147 - Nightdoor

Nightdoor can utilize Microsoft OneDrive or Google Drive for command and control purposes.

### S1130 - Raspberry Robin

Raspberry Robin second stage payloads can be hosted as RAR files, containing a malicious EXE and DLL, on Discord servers.

### S1240 - RedLine Stealer

RedLine Stealer has leveraged legitimate file sharing web services to host malicious payloads.

### S0649 - SMOKEDHAM

SMOKEDHAM has used Google Drive and Dropbox to host files downloaded by victims via malicious links.

### S0546 - SharpStage

SharpStage has used a legitimate web service for evading detection.

### S1178 - ShrinkLocker

ShrinkLocker uses a subdomain on the legitimate Cloudflare resource "trycloudflare[.]com" to obfuscate the threat actor's actual address and to tunnel information sent from victim systems.

### S0589 - Sibot

Sibot has used a legitimate compromised website to download DLLs to the victim's machine.

### S1086 - Snip3

Snip3 can download additional payloads from web services including Pastebin and top4top.

### S1124 - SocGholish

SocGholish has used Amazon Web Services to host second-stage servers.

### S0689 - WhisperGate

WhisperGate can download additional payloads hosted on a Discord channel.

### S0508 - ngrok

ngrok has been used by threat actors to proxy C2 connections to ngrok service subdomains.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0040 - APT41 DUST

APT41 DUST used compromised Google Workspace accounts for command and control.

### C0017 - C0017

During C0017, APT41 used the Cloudflare services for C2 communications.

### C0027 - C0027

During C0027, Scattered Spider downloaded tools from sites including file.io, GitHub, and paste.ee.

### C0005 - Operation Spalax

During Operation Spalax, the threat actors used OneDrive and MediaFire to host payloads.
