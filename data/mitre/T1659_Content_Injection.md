# T1659 - Content Injection

**Tactic:** Command and Control, Initial Access
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1659

## Description

Adversaries may gain access and continuously communicate with victims by injecting malicious content into systems through online network traffic. Rather than luring victims to malicious payloads hosted on a compromised website (i.e., Drive-by Target followed by Drive-by Compromise), adversaries may initially access victims through compromised data-transfer channels where they can manipulate traffic and/or inject their own content. These compromised online network channels may also be used to deliver additional payloads (i.e., Ingress Tool Transfer) and other data to already compromised systems.

Adversaries may inject content to victim systems in various ways, including:

* From the middle, where the adversary is in-between legitimate online client-server communications (**Note:** this is similar but distinct from Adversary-in-the-Middle, which describes AiTM activity solely within an enterprise environment)
* From the side, where malicious content is injected and races to the client as a fake response to requests of a legitimate online server

Content injection is often the result of compromised upstream communication channels, for example at the level of an internet service provider (ISP) as is the case with "lawful interception."

## Detection

### Detection Analytics

**Analytic 0992**

Detect suspicious file creations and process executions triggered by browser activity (e.g., injected payloads written to %AppData% or Temp directories, then executed). Correlate network anomalies with subsequent local process creation or script execution.

**Analytic 0993**

Detect curl/wget commands saving executable/script payloads to /tmp or /var/tmp followed by execution. Monitor packet captures or IDS/IPS alerts for injected responses or mismatched content types.

**Analytic 0994**

Monitor unified logs for processes spawned from Safari or other browsers that immediately load scripts or executables. Detect file drops in ~/Library/Caches or ~/Downloads that execute shortly after being written.


## Mitigations

### M1041 - Encrypt Sensitive Information

Where possible, ensure that online traffic is appropriately encrypted through services such as trusted VPNs.

### M1021 - Restrict Web-Based Content

Consider blocking download/transfer and execution of potentially uncommon file types known to be used in adversary campaigns.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1088 - Disco

Disco has achieved initial access and execution through content injection into DNS,  HTTP, and SMB replies to targeted hosts that redirect them to download malicious files.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
