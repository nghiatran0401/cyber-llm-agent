# T1135 - Network Share Discovery

**Tactic:** Discovery
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1135

## Description

Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement. Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network. 

File sharing over a Windows network occurs over the SMB protocol. Net can be used to query a remote system for available shared drives using the <code>net view \\\\remotesystem</code> command. It can also be used to query shared drives on the local system using <code>net share</code>. For macOS, the <code>sharing -l</code> command lists all shared points used for smb services.

## Detection

### Detection Analytics

**Analytic 0513**

Process or script enumerates network shares via CLI (net view/net share, PowerShell Get-SmbShare/WMI) or OS APIs (NetShareEnum/ srvsvc.NetShareEnumAll RPC) → bursts of outbound SMB/RPC connections (445/139, \\host\IPC$ / srvsvc) to many hosts inside a short window → optional follow-on file listing or copy operations.

**Analytic 0514**

CLI tools (smbclient -L, smbmap, rpcclient, nmblookup) or custom scripts enumerate SMB shares on many internal hosts → corresponding SMB connections (445/139) captured by Zeek/Netflow within a short window.

**Analytic 0515**

Use of native/mac tools (sharing -l, smbutil view, mount_smbfs) or scripts to enumerate SMB shares across many hosts, followed by outbound SMB connections observed in PF/Zeek logs.


## Mitigations

### M1028 - Operating System Configuration

Enable Windows Group Policy “Do Not Allow Anonymous Enumeration of SAM Accounts and Shares” security setting to limit users who can enumerate network shares.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1129 - Akira

Akira can identify remote file shares for encryption.

### S0640 - Avaddon

Avaddon has enumerated shared folders and mapped volumes.

### S1053 - AvosLocker

AvosLocker has enumerated shared drives on a compromised network.

### S1081 - BADHATCH

BADHATCH can check a user's access to the C$ share on a compromised machine.

### S0638 - Babuk

Babuk has the ability to enumerate network shares.

### S0606 - Bad Rabbit

Bad Rabbit enumerates open SMB shares on internal victim networks.

### S0534 - Bazar

Bazar can enumerate shared drives on the domain.

### S0570 - BitPaymer

BitPaymer can search for network shares on the domain or workgroup using <code>net view <host></code>.

### S1181 - BlackByte 2.0 Ransomware

BlackByte 2.0 Ransomware can identify network shares connected to the victim machine.

### S1180 - BlackByte Ransomware

BlackByte Ransomware can identify network shares connected to the victim machine.

### S1068 - BlackCat

BlackCat has the ability to discover network shares on compromised networks.

### S0660 - Clambling

Clambling has the ability to enumerate network shares.

### S0611 - Clop

Clop can enumerate network shares.

### S0154 - Cobalt Strike

Cobalt Strike can query shared drives on the local system.

### S0575 - Conti

Conti can enumerate remote open SMB network shares using <code>NetShareEnum()</code>.

### S0488 - CrackMapExec

CrackMapExec can enumerate the shared folders and associated permissions for a targeted network.

### S0625 - Cuba

Cuba can discover shared resources using the <code>NetShareEnum</code> API call.

### S0616 - DEATHRANSOM

DEATHRANSOM has the ability to use loop operations to enumerate network resources.

### S1159 - DUSTTRAP

DUSTTRAP can identify and enumerate victim system network shares.

### S0659 - Diavol

Diavol has a `ENMDSKS` command to enumerates available network shares.

### S1247 - Embargo

Embargo has searched for folders, subfolders and other networked or mounted drives for follow-on encryption actions.

### S0367 - Emotet

Emotet has enumerated non-hidden network shares using `WNetEnumResourceW`.

### S0363 - Empire

Empire can find shared drives on the local system.

### S0618 - FIVEHANDS

FIVEHANDS can enumerate network shares and mounted drives on a network.

### S0696 - Flagpro

Flagpro has been used to execute `net view` to discover mapped network shares.

### S0617 - HELLOKITTY

HELLOKITTY has the ability to enumerate network resources.

### S1139 - INC Ransomware

INC Ransomware has the ability to check for shared network drives to encrypt.

### S0483 - IcedID

IcedID has used the `net view /all` command to show available shares.

### S0260 - InvisiMole

InvisiMole can gather network share information.

### S1075 - KOPILUWAK

KOPILUWAK can use netstat and Net to discover network shares.

### S0250 - Koadic

Koadic can scan local network for open SMB.

### S0236 - Kwampirs

Kwampirs collects a list of network shares with the command <code>net share</code>.

### S1160 - Latrodectus

Latrodectus can run `C:\Windows\System32\cmd.exe /c net view /all` to discover network shares.

### S1199 - LockBit 2.0

LockBit 2.0 can discover remote shares.

### S1202 - LockBit 3.0

LockBit 3.0 can identify network shares on compromised systems.

### S1141 - LunarWeb

LunarWeb can identify shared resources in compromised environments.

### S0233 - MURKYTOP

MURKYTOP has the capability to retrieve information about shares on remote hosts.

### S1244 - Medusa Ransomware

Medusa Ransomware has identified networked drives.

### S0039 - Net

The <code>net view \\remotesystem</code> and <code>net share</code> commands in Net can be used to find shared drives and directories on remote and local systems respectively.

### S0165 - OSInfo

OSInfo discovers shares on the network

### S0365 - Olympic Destroyer

Olympic Destroyer will attempt to enumerate mapped network shares to later attempt to wipe all files on those shares.

### S0013 - PlugX

PlugX has a module to enumerate network shares.

### S0192 - Pupy

Pupy can list local and remote shared drives and folders over SMB.

### S0650 - QakBot

QakBot can use <code>net share</code> to identify network shares for use in lateral movement.

### S1242 - Qilin

Qilin has the ability to list network drives.

### S0686 - QuietSieve

QuietSieve can identify and search networked drives for specific file name extensions.

### S0458 - Ramsay

Ramsay can scan for network drives which may contain documents for collection.

### S1212 - RansomHub

RansomHub has the ability to target specific network shares for encryption.

### S1073 - Royal

Royal can enumerate the shared resources of a given IP addresses using the API call `NetShareEnum`.

### S0692 - SILENTTRINITY

SILENTTRINITY can enumerate shares on a compromised host.

### S1085 - Sardonic

Sardonic has the ability to execute the `net view` command.

### S0444 - ShimRat

ShimRat can enumerate connected drives for infected host machines.

### S0603 - Stuxnet

Stuxnet enumerates the directories of a network resource.

### S0266 - TrickBot

TrickBot module shareDll/mshareDll discovers network shares via the WNetOpenEnumA API.

### S0612 - WastedLocker

WastedLocker can identify network adjacent and accessible drives.

### S0689 - WhisperGate

WhisperGate can enumerate connected remote logical drives.

### S0251 - Zebrocy

Zebrocy identifies network drives when they are added to victim systems.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0015 - C0015

During C0015, the threat actors executed the PowerView ShareFinder module to identify open shares.

### C0049 - Leviathan Australian Intrusions

Leviathan scanned and enumerated remote network shares in victim environments during Leviathan Australian Intrusions.

### C0012 - Operation CuckooBees

During Operation CuckooBees, the threat actors used the `net share` command as part of their advanced reconnaissance.

### C0014 - Operation Wocao

During Operation Wocao, threat actors discovered network disks mounted to the system using netstat.
