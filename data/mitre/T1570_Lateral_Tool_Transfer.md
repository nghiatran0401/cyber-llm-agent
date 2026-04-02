# T1570 - Lateral Tool Transfer

**Tactic:** Lateral Movement
**Platforms:** ESXi, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1570

## Description

Adversaries may transfer tools or other files between systems in a compromised environment. Once brought into the victim environment (i.e., Ingress Tool Transfer) files may then be copied from one system to another to stage adversary tools or other files over the course of an operation.

Adversaries may copy files between internal victim systems to support lateral movement using inherent file sharing protocols such as file sharing over SMB/Windows Admin Shares to connected network shares or with authenticated connections via Remote Desktop Protocol.

Files can also be transferred using native or otherwise present tools on the victim system, such as scp, rsync, curl, sftp, and ftp. In some cases, adversaries may be able to leverage Web Services such as Dropbox or OneDrive to copy files from one machine to another via shared, automatically synced folders.

## Detection

### Detection Analytics

**Analytic 0516**

Correlate suspicious file transfers over SMB or Admin$ shares with process creation events (e.g., cmd.exe, powershell.exe, certutil.exe) that do not align with normal administrative behavior. Detect remote file writes followed by execution of transferred binaries.

**Analytic 0517**

Monitor scp, rsync, curl, sftp, or ftp processes initiating transfers to internal systems combined with file creation events in unusual directories. Correlate transfer activity with subsequent execution of those binaries.

**Analytic 0518**

Detect anomalous use of scp, rsync, curl, or third-party sync apps transferring executables into user directories. Correlate new file creation with immediate execution events.

**Analytic 0519**

Identify lateral transfer via datastore file uploads or internal scp/ssh sessions that result in new VMX/VMDK or script files. Correlate transfer with VM execution or datastore modification.


## Mitigations

### M1037 - Filter Network Traffic

Consider using the host firewall to restrict file sharing communications such as SMB.

### M1031 - Network Intrusion Prevention

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware or unusual data transfer over known tools and protocols like FTP can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0190 - BITSAdmin

BITSAdmin can be used to create BITS Jobs to upload and/or download files from SMB file servers.

### S1180 - BlackByte Ransomware

BlackByte Ransomware spreads itself laterally by writing the JavaScript launcher file to mapped shared folders.

### S1068 - BlackCat

BlackCat can replicate itself across connected servers via `psexec`.

### S0062 - DustySky

DustySky searches for network drives and removable media and duplicates itself onto them.

### S0367 - Emotet

Emotet has copied itself to remote systems using the `service.exe` filename.

### S0361 - Expand

Expand can be used to download or upload a file over a network share.

### S1229 - Havoc

Havoc has the ability to copy files from one location to another.

### S0698 - HermeticWizard

HermeticWizard can copy files to other machines on a compromised network.

### S1139 - INC Ransomware

INC Ransomware can push its encryption executable to multiple endpoints within compromised infrastructure.

### S1132 - IPsec Helper

IPsec Helper can download additional payloads from command and control nodes and execute them.

### S0357 - Impacket

Impacket has used its `wmiexec` command, leveraging Windows Management Instrumentation, to remotely stage and execute payloads in victim networks.

### S0372 - LockerGoga

LockerGoga has been observed moving around the victim network via SMB, indicating the actors behind this ransomware are manually copying files form computer to computer instead of self-propagating.

### S0532 - Lucifer

Lucifer can use certutil for propagation on Windows hosts within intranets.

### S0457 - Netwalker

Operators deploying Netwalker have used psexec to copy the Netwalker payload across accessible systems.

### S0365 - Olympic Destroyer

Olympic Destroyer attempts to copy itself to remote machines on the network.

### S1017 - OutSteel

OutSteel can download the Saint Bot malware for follow-on execution.

### S0029 - PsExec

PsExec can be used to download or upload a file over a network share.

### S0140 - Shamoon

Shamoon attempts to copy itself to remote machines on the network.

### S0603 - Stuxnet

Stuxnet uses an RPC server that contains a file dropping routine and support for payload version updates for P2P communications within a victim network.

### S1218 - VIRTUALPIE

VIRTUALPIE has file transfer capabilities.

### S1217 - VIRTUALPITA

VIRTUALPITA is capable of file transfer and arbitrary command execution.

### S0366 - WannaCry

WannaCry attempts to copy itself to remote computers after gaining access via an SMB exploit.

### S0106 - cmd

cmd can be used to copy files to/from a remotely connected internal system.

### S0404 - esentutl

esentutl can be used to copy files to/from a remote share.

### S0095 - ftp

ftp may be abused by adversaries to transfer tools or files between systems within a compromised environment.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0028 - 2015 Ukraine Electric Power Attack

During the 2015 Ukraine Electric Power Attack, Sandworm Team moved their tools laterally within the corporate network and between the ICS and corporate network.

### C0025 - 2016 Ukraine Electric Power Attack

During the 2016 Ukraine Electric Power Attack, Sandworm Team used `move` to transfer files to a network share.

### C0034 - 2022 Ukraine Electric Power Attack

During the 2022 Ukraine Electric Power Attack, Sandworm Team used a Group Policy Object (GPO) to copy CaddyWiper's executable `msserver.exe` from a staging server to a local hard drive before deployment.

### C0015 - C0015

During C0015, the threat actors used WMI to load Cobalt Strike onto additional hosts within a compromised network.

### C0018 - C0018

During C0018, the threat actors transferred the SoftPerfect Network Scanner and other tools to machines in the network using AnyDesk and PDQ Deploy.

### C0038 - HomeLand Justice

During HomeLand Justice, threat actors initiated a process named Mellona.exe to spread the ROADSWEEP file encryptor and a persistence script to a list of internal machines.

### C0014 - Operation Wocao

During Operation Wocao, threat actors used SMB to copy files to and from target systems.

### C0058 - SharePoint ToolShell Exploitation

During SharePoint ToolShell Exploitation, threat actors used Impacket to remotely stage and execute payloads via WMI.
