# T1518 - Software Discovery

**Tactic:** Discovery
**Platforms:** ESXi, IaaS, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1518

## Description

Adversaries may attempt to get a listing of software and software versions that are installed on a system or in a cloud environment. Adversaries may use the information from Software Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Such software may be deployed widely across the environment for configuration management or security reasons, such as Software Deployment Tools, and may allow adversaries broad access to infect devices or move laterally.

Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable to Exploitation for Privilege Escalation.

## Detection

### Detection Analytics

**Analytic 1100**

Adversary spawns a process or script to enumerate installed software using WMI, registry, or PowerShell, potentially followed by additional discovery or evasion behavior.

**Analytic 1101**

Adversary invokes 'dpkg -l', 'rpm -qa', or other package managers via shell or script to enumerate installed software.

**Analytic 1102**

Adversary runs 'system_profiler SPApplicationsDataType' or queries plist files to enumerate software via Terminal or scripts.

**Analytic 1103**

Adversary uses cloud-native APIs or CLI (e.g., AWS Systems Manager, Azure Resource Graph) to list installed software on cloud workloads.

**Analytic 1104**

Adversary uses 'esxcli software vib list' to enumerate installed VIBs, drivers, and modules.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0534 - Bazar

Bazar can query the Registry for installed applications.

### S0482 - Bundlore

Bundlore has the ability to enumerate what browser is being used as well as version information for Safari.

### S0674 - CharmPower

CharmPower can list the installed applications on a compromised host.

### S0154 - Cobalt Strike

The Cobalt Strike System Profiler can discover applications through the browser and identify the version of Java the target has.

### S0126 - ComRAT

ComRAT can check the victim's default browser to determine which process to inject its communications module into.

### S1153 - Cuckoo Stealer

Cuckoo Stealer has the ability to search systems for installed applications.

### S0384 - Dridex

Dridex has collected a list of installed software on the system.

### S0062 - DustySky

DustySky lists all installed software for the infected machine.

### S0024 - Dyre

Dyre has the ability to identify installed programs on a compromised host.

### S0431 - HotCroissant

HotCroissant can retrieve a list of applications from the <code>SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths</code> registry key.

### S0260 - InvisiMole

InvisiMole can collect information about installed software used by specific users, software executed on user login, and software executed by each system.

### S1245 - InvisibleFerret

InvisibleFerret has gathered installed programs and running processes.

### S0526 - KGH_SPY

KGH_SPY can collect information on installed applications.

### S1185 - LightSpy

If sent the command `16001`, LightSpy uses the `NSFileManger contentsOfDirectoryAtPath()` to enumerate the Applications folder to collect the bundle name, bundle identifier, and version information from each application's `info.plist` file. The results are then converted into a JSON blob for exfiltration.

### S1141 - LunarWeb

LunarWeb can list installed software on compromised systems.

### S0652 - MarkiRAT

MarkiRAT can check for the Telegram installation directory by enumerating the files on disk.

### S0455 - Metamorfo

Metamorfo has searched the compromised system for banking applications.

### S0229 - Orz

Orz can gather the victim's Internet Explorer version.

### S0598 - P.A.S. Webshell

P.A.S. Webshell can list PHP server configuration details.

### S1228 - PUBLOAD

PUBLOAD has used several commands executed in sequence via `cmd` in a short interval to gather software versions including querying Registry keys.

### S0650 - QakBot

QakBot can enumerate a list of installed programs.

### S0148 - RTM

RTM can scan victim drives to look for specific banking software on the machine to determine next actions.

### S1148 - Raccoon Stealer

Raccoon Stealer is capable of identifying running software on victim machines.

### S1240 - RedLine Stealer

RedLine Stealer can get a list of programs on the victim device.

### S1042 - SUGARDUMP

SUGARDUMP can identify Chrome, Opera, Edge Chromium, and Firefox browsers, including version number, on a compromised host.

### S1064 - SVCReady

SVCReady can collect a list of installed software from an infected host.

### S1099 - Samurai

Samurai can check for the presence and version of the .NET framework.

### S0445 - ShimRatReporter

ShimRatReporter gathered a list of installed software on the infected host.

### S0623 - Siloscape

Siloscape searches for the kubectl binary.

### S1124 - SocGholish

SocGholish can identify the victim's browser in order to serve the correct fake update page.

### S0646 - SpicyOmelette

SpicyOmelette can enumerate running software on a targeted system.

### S1183 - StrelaStealer

StrelaStealer variants use COM objects to enumerate installed applications from the "AppsFolder" on victim machines.

### S0467 - TajMahal

TajMahal has the ability to identify the Internet Explorer (IE) version on an infected host.

### S1065 - Woody RAT

Woody RAT can collect .NET, PowerShell, and Python information from an infected host.

### S0658 - XCSSET

XCSSET uses <code>ps aux</code> with the <code>grep</code> command to enumerate common browsers and system processes potentially impacting XCSSET's exfiltration capabilities.

### S0472 - down_new

down_new has the ability to gather information on installed applications.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0044 - Juicy Mix

During Juicy Mix, OilRig used browser data dumper tools to create a list of users with Google Chrome installed.

### C0016 - Operation Dust Storm

During Operation Dust Storm, the threat actors deployed a file called `DeployJava.js` to fingerprint installed software on a victim system prior to exploit delivery.

### C0014 - Operation Wocao

During Operation Wocao, threat actors collected a list of installed software on the infected system.
