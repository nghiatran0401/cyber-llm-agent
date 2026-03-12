# T1547 - Boot or Logon Autostart Execution

**Tactic:** Persistence, Privilege Escalation
**Platforms:** Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1547

## Description

Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon. These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. An adversary may achieve the same goal by modifying or extending features of the kernel.

Since some boot or logon autostart programs run with higher privileges, an adversary may leverage these to elevate privileges.

## Detection

### Detection Analytics

**Analytic 0764**

Correlation of registry key modification for Run/RunOnce with abnormal parent-child process relationships and outlier execution at user logon or system startup

**Analytic 0765**

Correlates creation/modification of systemd service files or /etc/init.d scripts with outlier process behavior during boot

**Analytic 0766**

Observes creation or modification of LaunchAgent/LaunchDaemon property list files combined with anomalous plist payload execution after user logon


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0651 - BoxCaon

BoxCaon established persistence by setting the <code>HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows\load</code> registry key to point to its executable.

### S0567 - Dtrack

Dtrack’s RAT makes a persistent target file with auto execution on the host start.

### S0084 - Mis-Type

Mis-Type has created registry keys for persistence, including `HKCU\Software\bkfouerioyou`, `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{6afa8072-b2b1-31a8-b5c1-{Unique Identifier}`, and `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{3BF41072-B2B1-31A8-B5C1-{Unique Identifier}`.

### S0083 - Misdat

Misdat has created registry keys for persistence, including `HKCU\Software\dnimtsoleht\StubPath`, `HKCU\Software\snimtsOleht\StubPath`, `HKCU\Software\Backtsaleht\StubPath`, `HKLM\SOFTWARE\Microsoft\Active Setup\Installed. Components\{3bf41072-b2b1-21c8-b5c1-bd56d32fbda7}`, and `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{3ef41072-a2f1-21c8-c5c1-70c2c3bc7905}`.

### S0653 - xCaon

xCaon has added persistence via the Registry key <code>HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows\load</code> which causes the malware to run each time any user logs in.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
