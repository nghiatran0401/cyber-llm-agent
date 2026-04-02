# T1124 - System Time Discovery

**Tactic:** Discovery
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1124

## Description

An adversary may gather the system time and/or time zone settings from a local or remote system. The system time is set and stored by services, such as the Windows Time Service on Windows or <code>systemsetup</code> on macOS. These time settings may also be synchronized between systems and services in an enterprise network, typically accomplished with a network time server within a domain.

System time information may be gathered in a number of ways, such as with Net on Windows by performing <code>net time \\hostname</code> to gather the system time on a remote system. The victim's time zone may also be inferred from the current system time or gathered by using <code>w32tm /tz</code>. In addition, adversaries can discover device uptime through functions such as <code>GetTickCount()</code> to determine how long it has been since the system booted up.

On network devices, Network Device CLI commands such as `show clock detail` can be used to see the current time configuration. On ESXi servers, `esxcli system clock get` can be used for the same purpose.

In addition, system calls – such as <code>time()</code> – have been used to collect the current time on Linux devices. On macOS systems, adversaries may use commands such as <code>systemsetup -gettimezone</code> or <code>timeIntervalSinceNow</code> to gather current time zone information or current date and time.

This information could be useful for performing other techniques, such as executing a file with a Scheduled Task/Job, or to discover locality information based on time zone to assist in victim targeting (i.e. System Location Discovery). Adversaries may also use knowledge of system time as part of a time bomb, or delaying execution until a specified date/time.

## Detection

### Detection Analytics

**Analytic 0430**

Untrusted or unusual process/script (cmd.exe, powershell.exe, w32tm.exe, net.exe, custom binaries) queries system time/timezone (e.g., w32tm /tz, net time \\host, Get-TimeZone, GetTickCount API) and (optionally) is followed within a short window by time-based scheduling or conditional execution (e.g., schtasks /create, at.exe, PowerShell Start-Sleep with large values).

**Analytic 0431**

A process (often spawned by a shell, interpreter, or malware implant) executes time discovery via commands (date, timedatectl, hwclock, cat /etc/timezone, /proc/uptime) or direct syscalls (time(), clock_gettime) and is (optionally) followed by scheduled task creation/modification (crontab, at) or conditional sleep logic.

**Analytic 0432**

Process/script execution of systemsetup -gettimezone, date, ioreg, or API usage (timeIntervalSinceNow, gettimeofday) followed by time-based scheduling (launchd plist modification) or sleep-based execution.

**Analytic 0433**

Interactive or remote shell/API invocation of esxcli system clock get or querying time parameters via hostd/vpxa shortly followed by time/ntp configuration checks or scheduled task creation, executed by non-standard accounts or outside maintenance windows.

**Analytic 0434**

Non-standard or rare users/locations issue CLI commands like "show clock detail" or "show timezone"; optionally followed by configuration of time/timezone or NTP sources. AAA/TACACS+ accounting and syslog correlate execution to identity, source IP, and privilege level.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0331 - Agent Tesla

Agent Tesla can collect the timestamp from the victim’s machine.

### S0622 - AppleSeed

AppleSeed can pull a timestamp from the victim's machine.

### S0373 - Astaroth

Astaroth collects the timestamp from the infected machine.

### S1053 - AvosLocker

AvosLocker has checked the system time before and after encryption.

### S0344 - Azorult

Azorult can collect the time zone information from the system.

### S1081 - BADHATCH

BADHATCH can obtain the `DATETIME` and `UPTIME` from a compromised machine.

### S0017 - BISCUIT

BISCUIT has a command to collect the system `UPTIME`.

### S0657 - BLUELIGHT

BLUELIGHT can collect the local time on a compromised host.

### S0534 - Bazar

Bazar can collect the time on the compromised host.

### S1246 - BeaverTail

BeaverTail has obtained and sent the current timestamp associated with the victim device to C2.

### S0574 - BendyBear

BendyBear has the ability to determine local time on a compromised host.

### S0268 - Bisonal

Bisonal can check the system time set on the infected host.

### S0351 - Cannon

Cannon can collect the current time zone information from the victim’s machine.

### S0335 - Carbon

Carbon uses the command <code>net time \\127.0.0.1</code> to get information the system’s time.

### S0660 - Clambling

Clambling can determine the current time.

### S0126 - ComRAT

ComRAT has checked the victim system's date and time to perform tasks during business hours (9 to 5, Monday to Friday).

### S0608 - Conficker

Conficker uses the current UTC victim system date for domain generation and connects to time servers to determine the current date.

### S0115 - Crimson

Crimson has the ability to determine the date and time on a compromised host.

### S1033 - DCSrv

DCSrv can compare the current time on an infected host with a configuration value to determine when to start the encryption process.

### S1134 - DEADWOOD

DEADWOOD will set a timestamp value to determine when wiping functionality starts. When the timestamp is met on the system, a trigger file is created on the operating system allowing for execution to proceed. If the timestamp is in the past, the wiper will execute immediately.

### S0694 - DRATzarus

DRATzarus can use the `GetTickCount` and `GetSystemTimeAsFileTime` API calls to inspect system time.

### S1159 - DUSTTRAP

DUSTTRAP reads the infected system's current time and writes it to a log file during execution.

### S1111 - DarkGate

DarkGate creates a log file for capturing keylogging, clipboard, and related data using the victim host's current date for the filename. DarkGate queries victim system epoch time during execution. DarkGate captures system time information as part of automated profiling on initial installation.

### S0673 - DarkWatchman

DarkWatchman can collect time zone information and system `UPTIME`.

### S0554 - Egregor

Egregor contains functionality to query the local/system time.

### S0091 - Epic

Epic uses the <code>net time</code> command  to get the system time from the machine and collect the current date and time zone information.

### S0396 - EvilBunny

EvilBunny has used the API calls NtQuerySystemTime, GetSystemTimeAsFileTime, and GetTickCount to gather time metrics as part of its checks to see if the malware is running in a sandbox.

### S0267 - FELIXROOT

FELIXROOT gathers the time zone information from the victim’s machine.

### S1044 - FunnyDream

FunnyDream can check system time to help determine when changes were made to specified files.

### S0417 - GRIFFON

GRIFFON has used a reconnaissance module that can be used to retrieve the date and time of the system.

### S0588 - GoldMax

GoldMax can check the current date-time value of the compromised system, comparing it to the hardcoded execution trigger and can send the current timestamp to the C2 server.

### S0531 - Grandoreiro

Grandoreiro can determine the time on the victim machine via IPinfo.

### S0237 - GravityRAT

GravityRAT can obtain the date and time of a system.

### S0690 - Green Lambert

Green Lambert can collect the date and time from a compromised host.

### S0376 - HOPLIGHT

HOPLIGHT has been observed collecting system time from victim machines.

### S0260 - InvisiMole

InvisiMole gathers the local system time from the victim’s machine.

### S1051 - KEYPLUG

KEYPLUG can obtain the current tick count of an infected computer.

### S1244 - Medusa Ransomware

Medusa Ransomware has discovered device uptime through `GetTickCount()`.

### S0455 - Metamorfo

Metamorfo uses JavaScript to get the system time.

### S0149 - MoonWind

MoonWind obtains the victim's current time.

### S0353 - NOKKI

NOKKI can collect the current timestamp of the victim's machine.

### S0039 - Net

The <code>net time</code> command can be used in Net to determine the local or remote system time.

### S1147 - Nightdoor

Nightdoor can identify the system local time information.

### S0439 - Okrum

Okrum can obtain the date and time of the compromised system.

### S0264 - OopsIE

OopsIE checks to see if the system is configured with "Daylight" time and checks for a specific region to be set for the timezone.

### S1233 - PAKLOG

PAKLOG has collected a timestamp to log the precise time a key was pressed, formatted as %Y-%m-%d %H:%M:%S.

### S1228 - PUBLOAD

PUBLOAD has collected the machine’s tick count through the use of `GetTickCount`.

### S0501 - PipeMon

PipeMon can send time zone information from a compromised host to C2.

### S0013 - PlugX

PlugX has identified system time through its GetSystemInfo command.

### S0139 - PowerDuke

PowerDuke has commands to get the time the machine was built, the time, and the time zone.

### S0238 - Proxysvc

As part of the data reconnaissance phase, Proxysvc grabs the system time to send back to the control server.

### S0650 - QakBot

QakBot can identify the system time on a targeted host.

### S0148 - RTM

RTM can obtain the victim time zone.

### S1148 - Raccoon Stealer

Raccoon Stealer gathers victim machine timezone information.

### S0450 - SHARPSTATS

SHARPSTATS has the ability to identify the current date and time on the compromised host.

### S0692 - SILENTTRINITY

SILENTTRINITY can collect start time information from a compromised host.

### S0559 - SUNBURST

SUNBURST collected device `UPTIME`.

### S1064 - SVCReady

SVCReady can collect time zone information.

### S0596 - ShadowPad

ShadowPad has collected the current date and time of the victim system.

### S0140 - Shamoon

Shamoon obtains the system time and will only activate if it is greater than a preset date.

### S1178 - ShrinkLocker

ShrinkLocker retrieves a system timestamp that is used in generating an encryption key.

### S0615 - SombRAT

SombRAT can execute <code>getinfo</code>  to discover the current time on a compromised host.

### S1227 - StarProxy

StarProxy has utilized the windows API call `GetLocalTime()` to retrieve a SystemTime structure to generate a seed value.

### S0380 - StoneDrill

StoneDrill can obtain the current date and time of the victim machine.

### S1034 - StrifeWater

StrifeWater can collect the time zone from the victim's machine.

### S0603 - Stuxnet

Stuxnet collects the time and date of a system when it is infected.

### S0098 - T9000

T9000 gathers and beacons the system time during installation.

### S0586 - TAINTEDSCRIBE

TAINTEDSCRIBE can execute <code>GetLocalTime</code> for time discovery.

### S0011 - Taidoor

Taidoor can use <code>GetLocalTime</code> and <code>GetSystemTime</code> to collect system time.

### S0467 - TajMahal

TajMahal has the ability to determine local time on a compromised host.

### S0678 - Torisma

Torisma can collect the current time on a victim machine.

### S0275 - UPPERCUT

UPPERCUT has the capability to obtain the time zone information and current timestamp of the victim’s machine.

### S0466 - WindTail

WindTail has the ability to generate the current date and time.

### S0251 - Zebrocy

Zebrocy gathers the current time zone and date information from the system.

### S0330 - Zeus Panda

Zeus Panda collects the current system time (UTC) and sends it back to the C2 server.

### S0471 - build_downer

build_downer has the ability to determine the local time to ensure malware installation only happens during the hours that the infected system is active.

### S1043 - ccf32

ccf32 can determine the local time on targeted machines.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0015 - C0015

During C0015, the threat actors used the command `net view /all time` to gather the local time of a compromised network.

### C0012 - Operation CuckooBees

During Operation CuckooBees, the threat actors used the `net time` command as part of their advanced reconnaissance.

### C0014 - Operation Wocao

During Operation Wocao, threat actors used the `time` command to retrieve the current time of a compromised system.
