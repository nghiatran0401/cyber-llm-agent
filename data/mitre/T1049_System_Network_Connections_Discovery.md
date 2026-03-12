# T1049 - System Network Connections Discovery

**Tactic:** Discovery
**Platforms:** ESXi, IaaS, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1049

## Description

Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network. 

An adversary who gains access to a system that is part of a cloud-based environment may map out Virtual Private Clouds or Virtual Networks in order to determine what systems and services are connected. The actions performed are likely the same types of discovery techniques depending on the operating system, but the resulting information may include details about the networked cloud environment relevant to the adversary's goals. Cloud providers may have different ways in which their virtual networks operate. Similarly, adversaries who gain access to network devices may also perform similar discovery activities to gather information about connected systems and services.

Utilities and commands that acquire this information include netstat, "net use," and "net session" with Net. In Mac and Linux, netstat and <code>lsof</code> can be used to list current connections. <code>who -a</code> and <code>w</code> can be used to show which users are currently logged in, similar to "net session". Additionally, built-in features native to network devices and Network Device CLI may be used (e.g. <code>show ip sockets</code>, <code>show tcp brief</code>). On ESXi servers, the command `esxi network ip connection list` can be used to list active network connections.

## Detection

### Detection Analytics

**Analytic 0903**

Detects usage of commands or binaries (e.g., netstat, PowerShell Get-NetTCPConnection) and WMI or API calls to enumerate local or remote network connections.

**Analytic 0904**

Detects use of netstat, ss, lsof, or custom shell scripts to list current network connections. Often paired with privilege escalation or staging.

**Analytic 0905**

Detects shell-based enumeration of active connections using `netstat`, `lsof -i`, or AppleScript-based system discovery.

**Analytic 0906**

Detects shell or API usage of `esxcli network ip connection list` or `netstat` to enumerate ESXi host connections.

**Analytic 0907**

Detects interactive or automated use of CLI commands like `show ip sockets`, `show tcp brief`, or SNMP queries for active sessions on routers/switches.

**Analytic 0908**

Detects enumeration of cloud network interfaces, VPCs, subnets, or peer connections using CLI or SDKs (e.g., AWS CLI, Azure CLI, GCloud CLI).


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0456 - Aria-body

Aria-body has the ability to gather TCP and UDP table status listings.

### S1081 - BADHATCH

BADHATCH can execute `netstat.exe -f` on a compromised machine.

### S0638 - Babuk

Babuk can use “WNetOpenEnumW” and “WNetEnumResourceW” to enumerate files in network resources for encryption.

### S0089 - BlackEnergy

BlackEnergy has gathered information about local network connections using netstat.

### S0335 - Carbon

Carbon uses the <code>netstat -r</code> and <code>netstat -an</code> commands.

### S0154 - Cobalt Strike

Cobalt Strike can produce a sessions report from compromised hosts.

### S0244 - Comnie

Comnie executes the <code>netstat -ano</code> command.

### S0575 - Conti

Conti can enumerate routine network connections from a compromised host.

### S0488 - CrackMapExec

CrackMapExec can discover active sessions for a targeted system.

### S0625 - Cuba

Cuba can use the function <code>GetIpNetTable</code> to recover the last connections to the victim's machine.

### S0567 - Dtrack

Dtrack can collect network and active connection information.

### S0038 - Duqu

The discovery modules used with Duqu can collect information on network connections.

### S0554 - Egregor

Egregor can enumerate all connected drives.

### S0363 - Empire

Empire can enumerate the current network connections of a host.

### S0091 - Epic

Epic uses the <code>net use</code>, <code>net session</code>, and <code>netstat</code> commands to gather information on network connections.

### S1144 - FRP

FRP can use a dashboard and U/I to display the status of connections from the FRP client and server.

### S0696 - Flagpro

Flagpro has been used to execute <code>netstat -ano</code> on a compromised host.

### S0237 - GravityRAT

GravityRAT uses the <code>netstat</code> command to find open ports on the victim’s machine.

### S0356 - KONNI

KONNI has used <code>net session</code> on the victim's machine.

### S1075 - KOPILUWAK

KOPILUWAK can use netstat, Arp, and Net to discover current TCP connections.

### S0236 - Kwampirs

Kwampirs collects a list of active and listening connections by using the command <code>netstat -nao</code> as well as a list of available network mappings with <code>net use</code>.

### S0681 - Lizar

Lizar has a plugin to retrieve information about all active network sessions on the infected server.

### S0532 - Lucifer

Lucifer can identify the IP and port numbers for all remote connections from the compromised host.

### S1141 - LunarWeb

LunarWeb can enumerate system network connections.

### S0443 - MESSAGETAP

After loading the keyword and phone data files, MESSAGETAP begins monitoring all network connections to and from the victim server.

### S1060 - Mafalda

Mafalda can use the <code>GetExtendedTcpTable</code> function to retrieve information about established TCP connections.

### S0449 - Maze

Maze has used the "WNetOpenEnumW", "WNetEnumResourceW”, “WNetCloseEnum” and “WNetAddConnection2W” functions to enumerate the network resources on the infected machine.

### S0198 - NETWIRE

NETWIRE can capture session logon details from a compromised host.

### S0039 - Net

Commands such as <code>net use</code> and <code>net session</code> can be used in Net to gather information about network connections from a particular host.

### S0165 - OSInfo

OSInfo enumerates the current network connections similar to <code> net use </code>.

### S0439 - Okrum

Okrum was seen using NetSess to discover NetBIOS sessions.

### S0184 - POWRUNER

POWRUNER may collect active network connections by running <code>netstat -an</code> on a victim.

### S1228 - PUBLOAD

PUBLOAD has used several commands executed in sequence via `cmd` in a short interval to gather information on network connections.

### S1091 - Pacu

Once inside a Virtual Private Cloud, Pacu can attempt to identify DirectConnect, VPN, or VPC Peering.

### S0013 - PlugX

PlugX has a module for enumerating TCP and UDP network connections and associated processes using the <code>netstat</code> command.

### S0378 - PoshC2

PoshC2 contains an implementation of netstat to enumerate TCP and UDP connections.

### S0192 - Pupy

Pupy has a built-in utility command for <code>netstat</code>, can do net session through PowerView, and has an interactive shell which can be used to discover additional information.

### S1032 - PyDCrypt

PyDCrypt has used netsh to find RPC connections on remote machines.

### S0650 - QakBot

QakBot can use <code>netstat</code> to enumerate current network connections.

### S0241 - RATANKBA

RATANKBA uses <code>netstat -ano</code> to search for specific IP address ranges.

### S0458 - Ramsay

Ramsay can use <code>netstat</code> to enumerate network connections.

### S0153 - RedLeaves

RedLeaves can enumerate drives and Remote Desktop sessions.

### S0125 - Remsec

Remsec can obtain a list of active connections and open ports.

### S0063 - SHOTPUT

SHOTPUT uses netstat to list TCP connection status.

### S0533 - SLOTHFULMEDIA

SLOTHFULMEDIA can enumerate open ports on a victim machine.

### S1085 - Sardonic

Sardonic has the ability to execute the `netstat` command.

### S0445 - ShimRatReporter

ShimRatReporter used the Windows function <code>GetExtendedUdpTable</code> to detect connected UDP endpoints.

### S0589 - Sibot

Sibot has retrieved a GUID associated with a present LAN connection on a compromised machine.

### S0633 - Sliver

Sliver can collect network connection information.

### S0374 - SpeakUp

SpeakUp uses the <code>arp -a</code> command.

### S0018 - Sykipot

Sykipot may use <code>netstat -ano</code> to display active network connections.

### S0678 - Torisma

Torisma can use `WTSEnumerateSessionsW` to monitor remote desktop connections.

### S0094 - Trojan.Karagany

Trojan.Karagany can use netstat to collect a list of network connections.

### S0452 - USBferry

USBferry can use <code>netstat</code> and <code>nbtstat</code> to detect active network connections.

### S0180 - Volgmer

Volgmer can gather information about TCP connection state.

### S0579 - Waterbear

Waterbear can use API hooks on `GetExtendedTcpTable` to retrieve a table containing a list of TCP endpoints available to the application.

### S0251 - Zebrocy

Zebrocy uses <code>netstat -aon</code> to gather network connection information.

### S0283 - jRAT

jRAT can list network connections.

### S0102 - nbtstat

nbtstat can be used to discover current NetBIOS sessions.

### S0104 - netstat

netstat can be used to enumerate local network connections, including active TCP connections and other network statistics.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0007 - FunnyDream

During FunnyDream, the threat actors used netstat to discover network connections on remote systems.

### C0012 - Operation CuckooBees

During Operation CuckooBees, the threat actors used the `net session`, `net use`, and `netstat` commands as part of their advanced reconnaissance.

### C0014 - Operation Wocao

During Operation Wocao, threat actors collected a list of open connections on the infected system using `netstat` and checks whether it has an internet connection.
