# T1104 - Multi-Stage Channels

**Tactic:** Command and Control
**Platforms:** ESXi, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1104

## Description

Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions. Use of multiple stages may obfuscate the command and control channel to make detection more difficult.

Remote access tools will call back to the first-stage command and control server for instructions. The first stage may have automated capabilities to collect basic host information, update tools, and upload additional files. A second remote access tool (RAT) could be uploaded at that point to redirect the host to the second-stage command and control server. The second stage will likely be more fully featured and allow the adversary to interact with the system through a reverse shell and additional RAT features.

The different stages will likely be hosted separately with no overlapping infrastructure. The loader may also have backup first-stage callbacks or Fallback Channels in case the original first-stage communication path is discovered and blocked.

## Detection

### Detection Analytics

**Analytic 0637**

Initial process initiates outbound connection to first-stage C2, receives payloads or commands, then spawns or injects into a second process that establishes a new outbound connection to an unrelated destination (second-stage C2).

**Analytic 0638**

Shell script or binary initiates curl/wget request to staging domain, writes output to disk or memory, and shortly afterward launches another process that establishes new outbound connection to a different IP or hostname.

**Analytic 0639**

Initial process using NSURLSession or similar APIs reaches out to known staging domains, followed by creation of a reverse shell or RAT connecting to a second unrelated server.

**Analytic 0640**

CLI-based or API-based network call from the hypervisor to external staging host, shortly followed by a connection to a second external IP by a spawned process or scheduled task.


## Mitigations

### M1031 - Network Intrusion Prevention

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0031 - BACKSPACE

BACKSPACE attempts to avoid detection by checking a first stage command and control server to determine if it should connect to the second stage server, which performs "louder" interactions with the malware.

### S0069 - BLACKCOFFEE

BLACKCOFFEE uses Microsoft’s TechNet Web portal to obtain an encoded tag containing the IP address of a command and control server and then communicates separately with that IP address for C2. If the C2 server is discovered or shut down, the threat actors can update the encoded IP address on TechNet to maintain control of the victims’ machines.

### S0534 - Bazar

The Bazar loader is used to download and execute the Bazar backdoor.

### S0220 - Chaos

After initial compromise, Chaos will download a second stage to establish a more permanent presence on the affected system.

### S1206 - JumbledPath

JumbledPath can communicate over a unique series of connections to send and retrieve data from exploited devices.

### S1160 - Latrodectus

Latrodectus has used a two-tiered C2 configuration with tier one nodes connecting to the victim and tier two nodes connecting to backend infrastructure.

### S1141 - LunarWeb

LunarWeb can use one C2 URL for first contact and to upload information about the host computer and two additional C2 URLs for getting commands.

### S1086 - Snip3

Snip3 can download and execute additional payloads and modules over separate communication channels.

### S0022 - Uroburos

Individual Uroburos implants can use multiple communication channels based on one of four available modes of operation.

### S0476 - Valak

Valak can download additional modules and malware capable of using separate C2 channels.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0056 - RedPenguin

During RedPenguin, UNC3886 used malware with separate channels to request and carry out tasks from C2.
