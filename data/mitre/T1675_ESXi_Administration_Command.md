# T1675 - ESXi Administration Command

**Tactic:** Execution
**Platforms:** ESXi
**Reference:** https://attack.mitre.org/techniques/T1675

## Description

Adversaries may abuse ESXi administration services to execute commands on guest machines hosted within an ESXi virtual environment. Persistent background services on ESXi-hosted VMs, such as the VMware Tools Daemon Service, allow for remote management from the ESXi server. The tools daemon service runs as `vmtoolsd.exe` on Windows guest operating systems, `vmware-tools-daemon` on macOS, and `vmtoolsd ` on Linux. 

Adversaries may leverage a variety of tools to execute commands on ESXi-hosted VMs – for example, by using the vSphere Web Services SDK to programmatically execute commands and scripts via APIs such as `StartProgramInGuest`, `ListProcessesInGuest`,  `ListFileInGuest`, and `InitiateFileTransferFromGuest`. This may enable follow-on behaviors on the guest VMs, such as File and Directory Discovery, Data from Local System, or OS Credential Dumping.

## Detection

### Detection Analytics

**Analytic 0646**

Detects anomalous usage of ESXi Guest Operations APIs such as StartProgramInGuest, ListProcessesInGuest, ListFileInGuest, or InitiateFileTransferFromGuest. Defender perspective focuses on unusual frequency of guest API calls, invocation from unexpected management accounts, or execution outside of business hours. These correlated signals indicate adversarial abuse of ESXi administrative services to run commands on guest VMs.


## Mitigations

### M1018 - User Account Management

If not required, restrict the permissions of users to perform Guest Operations on ESXi-hosted VMs.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1217 - VIRTUALPITA

VIRTUALPITA can execute commands on guest virtual machines from compromised ESXi hypervisors.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
