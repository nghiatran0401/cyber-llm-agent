# T1037 - Boot or Logon Initialization Scripts

**Tactic:** Persistence, Privilege Escalation
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1037

## Description

Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence. Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. These scripts can vary based on operating system and whether applied locally or remotely.  

Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary. 

An adversary may also be able to escalate their privileges since some boot or logon initialization scripts run with higher privileges.

## Detection

### Detection Analytics

**Analytic 0311**

Monitoring modification and execution of user or system logon scripts such as in registry Run keys or startup folders.

**Analytic 0312**

Detection of changes or execution of shell initialization scripts like .bashrc, .profile, or /etc/profile for persistence.

**Analytic 0313**

Monitoring for modification and execution of login hook scripts or LaunchAgents/LaunchDaemons used for persistence.

**Analytic 0314**

Detection of modification to ESXi rc.local.d or rc scripts that are used to execute on boot.

**Analytic 0315**

Detection of changes to device startup-config files that include boot scripts or scheduled execution routines.


## Mitigations

### M1022 - Restrict File and Directory Permissions

Restrict write access to logon scripts to specific administrators.

### M1024 - Restrict Registry Permissions

Ensure proper permissions are set for Registry hives to prevent users from modifying keys for logon scripts that may lead to persistence.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1078 - RotaJakiro

Depending on the Linux distribution and when executing with root permissions, RotaJakiro may install persistence using a `.conf` file in the `/etc/init/` folder.

### S1217 - VIRTUALPITA

VIRTUALPITA can persist as an init.d startup service on Linux vCenter systems.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0046 - ArcaneDoor

ArcaneDoor used malicious boot scripts to install the Line Runner backdoor on victim devices.
