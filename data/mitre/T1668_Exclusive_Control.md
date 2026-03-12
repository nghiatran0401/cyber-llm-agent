# T1668 - Exclusive Control

**Tactic:** Persistence
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1668

## Description

Adversaries who successfully compromise a system may attempt to maintain persistence by “closing the door” behind them  – in other words, by preventing other threat actors from initially accessing or maintaining a foothold on the same system. 

For example, adversaries may patch a vulnerable, compromised system to prevent other threat actors from leveraging that vulnerability in the future. They may “close the door” in other ways, such as disabling vulnerable services, stripping privileges from accounts, or removing other malware already on the compromised device.

Hindering other threat actors may allow an adversary to maintain sole access to a compromised system or network. This prevents the threat actor from needing to compete with or even being removed themselves by other threat actors. It also reduces the “noise” in the environment, lowering the possibility of being caught and evicted by defenders. Finally, in the case of Resource Hijacking, leveraging a compromised device’s full power allows the threat actor to maximize profit.

## Detection

### Detection Analytics

**Analytic 0045**

Detects unusual command executions and service modifications that indicate self-patching or disabling of vulnerable services post-compromise. Defenders should monitor for service stop commands, suspicious process termination, and execution of binaries or scripts aligned with known patching or service management tools outside of expected admin contexts.

**Analytic 0046**

Detects adversary attempts to monopolize control of compromised systems by issuing service stop commands, unloading vulnerable modules, or forcefully killing competing processes. Defenders should monitor audit logs and syslog for administrative utilities (systemctl, service, kill) being invoked outside of normal change management.

**Analytic 0047**

Detects unauthorized termination of system daemons or commands issued through launchctl or kill to stop competing services or malware processes. Defenders should monitor unified logs and EDR telemetry for unusual service modifications or terminations.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
