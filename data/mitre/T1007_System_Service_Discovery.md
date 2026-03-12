# T1007 - System Service Discovery

**Tactic:** Discovery
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1007

## Description

Adversaries may try to gather information about registered local system services. Adversaries may obtain information about services using tools as well as OS utility commands such as <code>sc query</code>, <code>tasklist /svc</code>, <code>systemctl --type=service</code>, and <code>net start</code>. Adversaries may also gather information about schedule tasks via commands such as `schtasks` on Windows or `crontab -l` on Linux and macOS.

Adversaries may use the information from System Service Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

## Detection

### Detection Analytics

**Analytic 1325**

Enumeration of services via native CLI tools (e.g., `sc query`, `tasklist /svc`, `net start`) or API calls via PowerShell and WMI.

**Analytic 1326**

Execution of service management commands like `systemctl list-units`, `service --status-all`, or direct reading of `/etc/init.d`.

**Analytic 1327**

Discovery via launchctl commands, or process enumeration using `ps aux | grep com.apple.` to identify daemons and services.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0127 - BBSRAT

BBSRAT can query service configuration information.

### S0638 - Babuk

Babuk can enumerate all services running on a compromised host.

### S0570 - BitPaymer

BitPaymer can enumerate existing Windows services on the host that are configured to run as LocalSystem.

### S1070 - Black Basta

Black Basta can check whether the service name `FAX` is present.

### S0572 - Caterpillar WebShell

Caterpillar WebShell can obtain a list of the services from a system.

### S0154 - Cobalt Strike

Cobalt Strike can enumerate services on compromised hosts.

### S0244 - Comnie

Comnie runs the command: <code>net start >> %TEMP%\info.dat</code> on a victim.

### S0625 - Cuba

Cuba can query service status using <code>QueryServiceStatusEx</code> function.

### S1066 - DarkTortilla

DarkTortilla can retrieve information about a compromised system's running services.

### S0024 - Dyre

Dyre has the ability to identify running services on a compromised host.

### S0081 - Elise

Elise executes <code>net start</code> after initial communication is made to the remote server.

### S1247 - Embargo

Embargo has obtained active services running on the victim’s system through the functions `OpenSCManagerW()` and `EnumServicesStatusExW()`.

### S0082 - Emissary

Emissary has the capability to execute the command <code>net start</code> to interact with services.

### S0091 - Epic

Epic uses the <code>tasklist /svc</code> command to list the services on the system.

### S0049 - GeminiDuke

GeminiDuke collects information on programs and services on the victim that are configured to automatically run at startup.

### S0237 - GravityRAT

GravityRAT has a feature to list the available services on the system.

### S0342 - GreyEnergy

GreyEnergy enumerates all Windows services.

### S1027 - Heyoka Backdoor

Heyoka Backdoor can check if it is running as a service on a compromised host.

### S0431 - HotCroissant

HotCroissant has the ability to retrieve a list of services on the infected host.

### S0203 - Hydraq

Hydraq creates a backdoor through which remote attackers can monitor services.

### S0398 - HyperBro

HyperBro can list all services and their configurations.

### S0260 - InvisiMole

InvisiMole can obtain running services on the victim.

### S0015 - Ixeshe

Ixeshe can list running services.

### S0201 - JPIN

JPIN can list running services.

### S0236 - Kwampirs

Kwampirs collects a list of running services with the command <code>tasklist /svc</code>.

### S0582 - LookBack

LookBack can enumerate services on the victim machine.

### S1244 - Medusa Ransomware

Medusa Ransomware has leveraged an encoded list of services that it designates for termination.

### S0039 - Net

The <code>net start</code> command can be used in Net to find information about Windows services.

### S1228 - PUBLOAD

PUBLOAD has leveraged `tasklist` to gather running services on victim host.

### S0378 - PoshC2

PoshC2 can enumerate service and service permission information.

### S1242 - Qilin

Qilin can identify specific services for termination or to be left running at execution.

### S0241 - RATANKBA

RATANKBA uses <code>tasklist /svc</code> to display running tasks.

### S0496 - REvil

REvil can enumerate active services.

### S0629 - RainyDay

RainyDay can create and register a service for execution.

### S0085 - S-Type

S-Type runs the command <code>net start</code> on a victim.

### S0692 - SILENTTRINITY

SILENTTRINITY can search for modifiable services that could be used for privilege escalation.

### S0533 - SLOTHFULMEDIA

SLOTHFULMEDIA has the capability to enumerate services.

### S0559 - SUNBURST

SUNBURST collected a list of service names that were hashed using a FNV-1a + XOR algorithm to check against similarly-hashed hardcoded blocklists.

### S1085 - Sardonic

Sardonic has the ability to execute the `net start` command.

### S0615 - SombRAT

SombRAT can enumerate services on a victim machine.

### S0018 - Sykipot

Sykipot may use <code>net start</code> to display running services.

### S0242 - SynAck

SynAck enumerates all running services.

### S0663 - SysUpdate

SysUpdate can collect a list of services on a victim machine.

### S0057 - Tasklist

Tasklist can be used to discover services running on a system.

### S0266 - TrickBot

TrickBot collects a list of install programs and services on the system’s machine.

### S0386 - Ursnif

Ursnif has gathered information about running services.

### S0180 - Volgmer

Volgmer queries the system to identify existing services.

### S0219 - WINERACK

WINERACK can enumerate services.

### S0086 - ZLib

ZLib has the ability to discover and manipulate Windows services.

### S0412 - ZxShell

ZxShell can check the services on the system.

### S0283 - jRAT

jRAT can list local services.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0012 - Operation CuckooBees

During Operation CuckooBees, the threat actors used the `net start` command as part of their initial reconnaissance.

### C0014 - Operation Wocao

During Operation Wocao, threat actors used the `tasklist` command to search for one of its backdoors.
