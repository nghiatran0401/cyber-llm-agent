# T1018 - Remote System Discovery

**Tactic:** Discovery
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1018

## Description

Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used such as  Ping, <code>net view</code> using Net, or, on ESXi servers, `esxcli network diag ping`.

Adversaries may also analyze data from local host files (ex: <code>C:\Windows\System32\Drivers\etc\hosts</code> or <code>/etc/hosts</code>) or other passive means (such as local Arp cache entries) in order to discover the presence of remote systems in an environment.

Adversaries may also target discovery of network infrastructure as well as leverage Network Device CLI commands on network devices to gather detailed information about systems within a network (e.g. <code>show cdp neighbors</code>, <code>show arp</code>).

## Detection

### Detection Analytics

**Analytic 1583**

Execution of network enumeration utilities (e.g., net.exe, ping.exe, tracert.exe) in short succession, often chained with lateral movement tools or system enumeration commands.

**Analytic 1584**

Use of bash scripts or interactive shells to issue sequential ping, arp, or traceroute commands to map remote hosts.

**Analytic 1585**

Execution of built-in or AppleScript-based system enumeration via `arp`, `netstat`, `ping`, and discovery of `/etc/hosts` contents.

**Analytic 1586**

ESXi shell or SSH access issuing `esxcli network diag ping` or viewing routing tables to identify connected hosts.

**Analytic 1587**

Execution of discovery commands like `show cdp neighbors`, `show arp`, and other interface-level introspection on Cisco or Juniper devices.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0552 - AdFind

AdFind has the ability to query Active Directory for computers.

### S0099 - Arp

Arp can be used to display a host's ARP cache, which may include address resolutions for remote systems.

### S1081 - BADHATCH

BADHATCH can use a PowerShell object such as, `System.Net.NetworkInformation.Ping` to ping a computer.

### S0093 - Backdoor.Oldrea

Backdoor.Oldrea can enumerate and map ICS-specific systems in victim environments.

### S0534 - Bazar

Bazar can enumerate remote systems using <code> Net View</code>.

### S0570 - BitPaymer

BitPaymer can use <code>net view</code> to discover remote systems.

### S1070 - Black Basta

Black Basta can use LDAP queries to connect to AD and iterate over connected workstations.

### S1068 - BlackCat

BlackCat can broadcasts NetBIOS Name Service (NBNC) messages to search for servers connected to compromised networks.

### S0521 - BloodHound

BloodHound can enumerate and collect the properties of domain computers, including domain controllers.

### S0335 - Carbon

Carbon uses the <code>net view</code> command.

### S0154 - Cobalt Strike

Cobalt Strike uses the native Windows Network Enumeration APIs to interrogate and discover targets in a Windows Active Directory network.

### S0244 - Comnie

Comnie runs the <code>net view</code> command

### S0575 - Conti

Conti has the ability to discover hosts on a target network.

### S0488 - CrackMapExec

CrackMapExec can discover active IP addresses, along with the machine name, within a targeted network.

### S0694 - DRATzarus

DRATzarus can search for other machines connected to compromised host and attempt to map the network.

### S1159 - DUSTTRAP

DUSTTRAP can use `ping` to identify remote hosts within the victim network.

### S0659 - Diavol

Diavol can use the ARP table to find remote hosts to scan.

### S0091 - Epic

Epic uses the <code>net view</code> command on the victim’s machine.

### S0696 - Flagpro

Flagpro has been used to execute <code>net view</code> on a targeted system.

### S1044 - FunnyDream

FunnyDream can collect information about hosts on the victim network.

### S1198 - Gomir

Gomir probes arbitrary network endpoints for TCP connectivity.

### S1229 - Havoc

Havoc features a module capable of host enumeration.

### S0698 - HermeticWizard

HermeticWizard can find machines on the local network by gathering known local IP addresses through `DNSGetCacheDataTable`, `GetIpNetTable`,`WNetOpenEnumW(RESOURCE_GLOBALNET, RESOURCETYPE_ANY)`,`NetServerEnum`,`GetTcpTable`, and `GetAdaptersAddresses.`

### S0604 - Industroyer

Industroyer can enumerate remote computers in the compromised network.

### S0599 - Kinsing

Kinsing has used a script to parse files like <code>/etc/hosts</code> and SSH <code>known_hosts</code> to discover remote systems.

### S0236 - Kwampirs

Kwampirs collects a list of available servers with the command <code>net view</code>.

### S0233 - MURKYTOP

MURKYTOP has the capability to identify remote hosts on connected networks.

### S1146 - MgBot

MgBot includes modules for performing ARP scans of local connected systems.

### S0590 - NBTscan

NBTscan can list NetBIOS computer names.

### S0039 - Net

Commands such as <code>net view</code> can be used in Net to gather information about available remote systems.

### S0359 - Nltest

Nltest may be used to enumerate remote domain controllers using options such as <code>/dclist</code> and <code>/dsgetdc</code>.

### S0165 - OSInfo

OSInfo performs a connection test to discover remote systems in the network

### S0365 - Olympic Destroyer

Olympic Destroyer uses Windows Management Instrumentation to enumerate all systems in the network.

### S0097 - Ping

Ping can be used to identify remote systems within a network.

### S0428 - PoetRAT

PoetRAT used Nmap for remote system discovery.

### S0650 - QakBot

QakBot can identify remote systems through the <code>net view</code> command.

### S1242 - Qilin

Qilin can enumerate domain-connected hosts during its discovery phase.

### S0241 - RATANKBA

RATANKBA runs the <code>net view /domain</code> and <code>net view</code> commands.

### S0684 - ROADTools

ROADTools can enumerate Azure AD systems and devices.

### S1212 - RansomHub

RansomHub can enumerate all accessible machines from the infected system.

### S0125 - Remsec

Remsec can ping or traceroute a remote host.

### S0063 - SHOTPUT

SHOTPUT has a command to list all servers in the domain, as well as one to locate domain controllers on a domain.

### S0692 - SILENTTRINITY

SILENTTRINITY can enumerate and collect the properties of domain computers.

### S0140 - Shamoon

Shamoon scans the C-class subnet of the IPs on the victim's interfaces.

### S0646 - SpicyOmelette

SpicyOmelette can identify payment systems, payment gateways, and ATM systems in compromised environments.

### S0018 - Sykipot

Sykipot may use <code>net view /domain</code> to display hostnames of available systems on a network.

### S0586 - TAINTEDSCRIBE

The TAINTEDSCRIBE command and execution module can perform target system enumeration.

### S0266 - TrickBot

TrickBot can enumerate computers and network devices.

### S0452 - USBferry

USBferry can use <code>net view</code> to gather information about remote systems.

### S0366 - WannaCry

WannaCry scans its local network segment for remote systems to try to exploit and copy itself to.

### S0385 - njRAT

njRAT can identify remote hosts on connected networks.

### S0248 - yty

yty uses the <code>net view</code> command for discovery.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0028 - 2015 Ukraine Electric Power Attack

During the 2015 Ukraine Electric Power Attack, Sandworm Team remotely discovered systems over LAN connections. OT systems were visible from the IT network   as well, giving adversaries the ability to discover operational assets.

### C0025 - 2016 Ukraine Electric Power Attack

During the 2016 Ukraine Electric Power Attack, Sandworm Team checked for connectivity to resources within the network and used LDAP to query Active Directory, discovering information about computers listed in AD.

### C0015 - C0015

During C0015, the threat actors used the commands `net view /all /domain` and `ping` to discover remote systems. They also used PowerView's PowerShell Invoke-ShareFinder script for file share enumeration.

### C0007 - FunnyDream

During FunnyDream, the threat actors used several tools and batch files to map victims' internal networks.

### C0049 - Leviathan Australian Intrusions

Leviathan performed extensive remote host enumeration to build their own map of victim networks during Leviathan Australian Intrusions.

### C0012 - Operation CuckooBees

During Operation CuckooBees, the threat actors used the `net view` and `ping` commands as part of their advanced reconnaissance.

### C0014 - Operation Wocao

During Operation Wocao, threat actors used `nbtscan` and `ping` to discover remote systems, as well as `dsquery subnet` on a domain controller to retrieve all subnets in the Active Directory.

### C0024 - SolarWinds Compromise

During the SolarWinds Compromise, APT29 used AdFind to enumerate remote systems.
