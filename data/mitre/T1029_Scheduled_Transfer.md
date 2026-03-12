# T1029 - Scheduled Transfer

**Tactic:** Exfiltration
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1029

## Description

Adversaries may schedule data exfiltration to be performed only at certain times of day or at certain intervals. This could be done to blend traffic patterns with normal activity or availability.

When scheduled exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as Exfiltration Over C2 Channel or Exfiltration Over Alternative Protocol.

## Detection

### Detection Analytics

**Analytic 1118**

Recurring network exfiltration initiated by scheduled or script-based processes exhibiting time-based regularity and consistent external destinations.

**Analytic 1119**

Detection of cron-based or script-based recurring transfers where the same script, user, or destination reappears at predictable intervals.

**Analytic 1120**

LaunchAgent or launchd recurring jobs initiating data transfer to consistent external IPs or domains with repeat timing signatures.


## Mitigations

### M1031 - Network Intrusion Prevention

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary command and control infrastructure and malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool command and control signatures over time or construct protocols in such a way to avoid detection by common defensive tools.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0045 - ADVSTORESHELL

ADVSTORESHELL collects, compresses, encrypts, and exfiltrates data to the C2 server every 10 minutes.

### S0667 - Chrommme

Chrommme can set itself to sleep before requesting a new command from C2.

### S0154 - Cobalt Strike

Cobalt Strike can set its Beacon payload to reach out to the C2 server on an arbitrary and random interval.

### S0126 - ComRAT

ComRAT has been programmed to sleep outside local business hours (9 to 5, Monday to Friday).

### S0200 - Dipsind

Dipsind can be configured to only run during normal working hours, which would make its communications harder to distinguish from normal traffic.

### S0696 - Flagpro

Flagpro has the ability to wait for a specified time interval between communicating with and executing commands from C2.

### S0265 - Kazuar

Kazuar can sleep for a specific time and be set to communicate at specific intervals.

### S0395 - LightNeuron

LightNeuron can be configured to exfiltrate data during nighttime or working hours.

### S0211 - Linfo

Linfo creates a backdoor through which remote attackers can change the frequency at which compromised hosts contact remote C2 infrastructure.

### S0409 - Machete

Machete sends stolen data to the C2 server every 10 minutes.

### S1100 - Ninja

Ninja can configure its agent to work only in specific time frames.

### S0223 - POWERSTATS

POWERSTATS can sleep for a given number of seconds.

### S0596 - ShadowPad

ShadowPad has sent data back to C2 every 8 hours.

### S1019 - Shark

Shark can pause C2 communications for a specified time.

### S0444 - ShimRat

ShimRat can sleep when instructed to do so by the C2.

### S0668 - TinyTurla

TinyTurla contacts its C2 based on a scheduled timing set in its configuration.

### S0283 - jRAT

jRAT can be configured to reconnect at certain intervals.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
