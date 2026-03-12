# T1197 - BITS Jobs

**Tactic:** Defense Evasion, Persistence
**Platforms:** Windows
**Reference:** https://attack.mitre.org/techniques/T1197

## Description

Adversaries may abuse BITS jobs to persistently execute code and perform various background tasks. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM). BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.

The interface to create and manage BITS jobs is accessible through PowerShell and the BITSAdmin tool.

Adversaries may abuse BITS to download (e.g. Ingress Tool Transfer), execute, and even clean up after running malicious code (e.g. Indicator Removal). BITS tasks are self-contained in the BITS job database, without new files or registry modifications, and often permitted by host firewalls. BITS enabled execution may also enable persistence by creating long-standing jobs (the default maximum lifetime is 90 days and extendable) or invoking an arbitrary program when a job completes or errors (including after system reboots).

BITS upload functionalities can also be used to perform Exfiltration Over Alternative Protocol.

## Detection

### Detection Analytics

**Analytic 0274**

Behavioral chain: (1) An actor creates or modifies a BITS job via bitsadmin.exe, PowerShell BITS cmdlets, or COM; (2) the job performs HTTP(S)/SMB network transfers while the owning user is logged on; (3) upon job completion/error, BITS launches a notify command (SetNotifyCmdLine) from svchost.exe -k netsvcs -s BITS, often establishing persistence by keeping long-lived jobs. The strategy correlates process creation, command/script telemetry, BITS-Client operational events, and network connections initiated by BITS.


## Mitigations

### M1037 - Filter Network Traffic

Modify network and/or host firewall rules, as well as other network controls, to only allow legitimate BITS traffic.

### M1028 - Operating System Configuration

Consider reducing the default BITS job lifetime in Group Policy or by editing the <code>JobInactivityTimeout</code> and <code>MaxDownloadTime</code> Registry values in <code> HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\BITS</code>.

### M1018 - User Account Management

Consider limiting access to the BITS interface to specific users or groups.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0190 - BITSAdmin

BITSAdmin can be used to create BITS Jobs to launch a malicious process.

### S0534 - Bazar

Bazar has been downloaded via Windows BITS functionality.

### S0154 - Cobalt Strike

Cobalt Strike can download a hosted "beacon" payload using BITSAdmin.

### S0554 - Egregor

Egregor has used BITSadmin to download and execute malicious DLLs.

### S0201 - JPIN

A JPIN variant downloads the backdoor payload via the BITS service.

### S0652 - MarkiRAT

MarkiRAT can use BITS Utility to connect with the C2 server.

### S0654 - ProLock

ProLock can use BITS jobs to download its malicious payload.

### S0333 - UBoatRAT

UBoatRAT takes advantage of the /SetNotifyCmdLine option in BITSAdmin to ensure it stays running on a system to maintain persistence.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
