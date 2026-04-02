# T1529 - System Shutdown/Reboot

**Tactic:** Impact
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1529

## Description

Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems. Operating systems may contain commands to initiate a shutdown/reboot of a machine or network device. In some cases, these commands may also be used to initiate a shutdown/reboot of a remote computer or network device via Network Device CLI (e.g. <code>reload</code>). They may also include shutdown/reboot of a virtual machine via hypervisor / cloud consoles or command line tools.

Shutting down or rebooting systems may disrupt access to computer resources for legitimate users while also impeding incident response/recovery.

Adversaries may also use Windows API functions, such as `InitializeSystemShutdownExW` or `ExitWindowsEx`, to force a system to shut down or reboot. Alternatively, the `NtRaiseHardError`or `ZwRaiseHardError` Windows API functions with the `ResponseOption` parameter set to `OptionShutdownSystem` may deliver a “blue screen of death” (BSOD) to a system. In order to leverage these API functions, an adversary may need to acquire `SeShutdownPrivilege` (e.g., via Access Token Manipulation).
 In some cases, the system may not be able to boot again. 

Adversaries may attempt to shutdown/reboot a system after impacting it in other ways, such as Disk Structure Wipe or Inhibit System Recovery, to hasten the intended effects on system availability.

## Detection

### Detection Analytics

**Analytic 1538**

Correlate process execution of shutdown/reboot commands (e.g., shutdown.exe, restart-computer) with host status change logs (Event IDs 1074, 6006) and absence of related administrative context (e.g., user not in Helpdesk group).

**Analytic 1539**

Detect 'shutdown', 'reboot', or 'systemctl poweroff' executions with auditd/syslog and absence of scheduled maintenance windows or approved user context.

**Analytic 1540**

Identify use of 'shutdown', 'reboot', or 'osascript' system shutdown invocations within unified logs and track unexpected shutdown sequences initiated by GUI or script. Cross-reference with user activity or absence thereof.

**Analytic 1541**

Detect commands such as 'esxcli system shutdown' or 'vim-cmd vmsvc/power.shutdown' executed outside of maintenance windows or via unusual users. Reboot logs in hostd.log and shell logs should be correlated.

**Analytic 1542**

Monitor CLI 'reload' commands issued without scheduled maintenance, and correlate to TACACS+/AAA logs for privilege validation.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1167 - AcidPour

AcidPour includes functionality to reboot the victim system following wiping actions, similar to AcidRain.

### S1125 - AcidRain

AcidRain reboots the target system once the various wiping processes are complete.

### S1133 - Apostle

Apostle reboots the victim machine following wiping and related activity.

### S1053 - AvosLocker

AvosLocker’s Linux variant has terminated ESXi virtual machines.

### S1136 - BFG Agonizer

BFG Agonizer uses elevated privileges to call <code>NtRaiseHardError</code> to induce a "blue screen of death" on infected systems, causing a system crash. Once shut down, the system is no longer bootable.

### S1070 - Black Basta

Black Basta has used `ShellExecuteA` to shut down and restart the victim system.

### S1149 - CHIMNEYSWEEP

CHIMNEYSWEEP can reboot or shutdown the targeted system or logoff the current user.

### S1033 - DCSrv

DCSrv has a function to sleep for two hours before rebooting the system.

### S1111 - DarkGate

DarkGate has used the `shutdown`command to shut down and/or restart the victim system.

### S0697 - HermeticWiper

HermeticWiper can initiate a system shutdown.

### S0607 - KillDisk

KillDisk attempts to reboot the machine by terminating specific processes.

### S1160 - Latrodectus

Latrodectus has the ability to restart compromised hosts.

### S0372 - LockerGoga

LockerGoga has been observed shutting down infected systems.

### S0582 - LookBack

LookBack can shutdown and reboot the victim machine.

### S0449 - Maze

Maze has issued a shutdown command on a victim machine that, upon reboot, will run the ransomware within a VM.

### S1135 - MultiLayer Wiper

MultiLayer Wiper reboots the infected system following wiping and related tasks to prevent system recovery.

### S0368 - NotPetya

NotPetya will reboot the system one hour after infection.

### S0365 - Olympic Destroyer

Olympic Destroyer will shut down the compromised system after it is done modifying system configuration settings.

### S1242 - Qilin

Qilin can initiate a reboot of the backup server to hinder recovery.

### S0140 - Shamoon

Shamoon will reboot the infected system once the wiping functionality has been completed.

### S1178 - ShrinkLocker

ShrinkLocker can restart the victim system if it encounters an error during execution, and will forcibly shutdown the system following encryption to lock out victim users.

### S0689 - WhisperGate

WhisperGate can shutdown a compromised host through execution of `ExitWindowsEx` with the `EXW_SHUTDOWN` flag.

### S1207 - XLoader

XLoader can initiate a system reboot or shutdown.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
