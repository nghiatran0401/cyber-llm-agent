# T1016 - System Network Configuration Discovery

**Tactic:** Discovery
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1016

## Description

Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include Arp, ipconfig/ifconfig, nbtstat, and route.

Adversaries may also leverage a Network Device CLI on network devices to gather information about configurations and settings, such as IP addresses of configured interfaces and static/dynamic routes (e.g. <code>show ip route</code>, <code>show ip interface</code>). On ESXi, adversaries may leverage esxcli to gather network configuration information. For example, the command `esxcli network nic list` will retrieve the MAC address, while `esxcli network ip interface ipv4 get` will retrieve the local IPv4 address.

Adversaries may use the information from System Network Configuration Discovery during automated discovery to shape follow-on behaviors, including determining certain access within the target network and what actions to do next.

## Detection

### Detection Analytics

**Analytic 0559**

Execution of built-in tools (e.g., ipconfig, route, netsh) or PowerShell/WMI queries to enumerate IP, MAC, interface status, or routing configuration.

**Analytic 0560**

Execution of `ifconfig`, `ip a`, or access to `/proc/net/` indicating collection of local interface and route configuration.

**Analytic 0561**

Execution of `ifconfig`, `networksetup`, or `system_profiler` to query IP/MAC/interface configuration and status.

**Analytic 0562**

Use of `esxcli network` commands (e.g., `esxcli network nic list`, `esxcli network ip interface ipv4 get`) via SSH or hostd to enumerate adapter and IP information.

**Analytic 0563**

CLI-based execution of interface and routing discovery commands (e.g., `show ip interface`, `show arp`, `show route`) over Telnet, SSH, or console.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1028 - Action RAT

Action RAT has the ability to collect the MAC address of an infected host.

### S0552 - AdFind

AdFind can extract subnet information from Active Directory.

### S0331 - Agent Tesla

Agent Tesla can collect the IP address of the victim machine and spawn instances of netsh.exe to enumerate wireless settings.

### S0092 - Agent.btz

Agent.btz collects the network adapter’s IP and MAC address as well as IP addresses of the network adapter’s default gateway, primary/secondary WINS, DHCP, and DNS servers, and saves them into a log file.

### S1025 - Amadey

Amadey can identify the IP address of a victim machine.

### S0504 - Anchor

Anchor can determine the public IP and location of a compromised host.

### S0622 - AppleSeed

AppleSeed can identify the IP of a targeted system.

### S0456 - Aria-body

Aria-body has the ability to identify the location, public IP address, and domain name on a compromised host.

### S0099 - Arp

Arp can be used to display ARP configuration information on the host.

### S0373 - Astaroth

Astaroth collects the external IP address from the system.

### S0640 - Avaddon

Avaddon can collect the external IP address of the victim.

### S0473 - Avenger

Avenger can identify the domain of the compromised host.

### S0344 - Azorult

Azorult can collect host IP information from the victim’s machine.

### S0245 - BADCALL

BADCALL collects the network adapter information.

### S0642 - BADFLICK

BADFLICK has captured victim IP address details.

### S0520 - BLINDINGCAN

BLINDINGCAN has collected the victim machine's local IP address information and MAC address.

### S0657 - BLUELIGHT

BLUELIGHT can collect IP information from the victim’s machine.

### S1184 - BOLDMOVE

BOLDMOVE enumerates network interfaces on the infected host.

### S0414 - BabyShark

BabyShark has executed the <code>ipconfig /all</code> command.

### S0093 - Backdoor.Oldrea

Backdoor.Oldrea collects information about the Internet adapter configuration.

### S0234 - Bandook

Bandook has a command to get the public IP address from a system.

### S0534 - Bazar

Bazar can collect the IP address and NetBIOS name of an infected machine.

### S0268 - Bisonal

Bisonal can execute <code>ipconfig</code> on the victim’s machine.

### S0089 - BlackEnergy

BlackEnergy has gathered information about network IP configurations using ipconfig.exe and about routing tables using route.exe.

### S0486 - Bonadan

Bonadan can find the external IP address of the infected host.

### S0651 - BoxCaon

BoxCaon can collect the victim's MAC address by using the <code>GetAdaptersInfo</code> API.

### S0252 - Brave Prince

Brave Prince gathers network configuration information as well as the ARP cache.

### S0274 - Calisto

Calisto runs the <code>ifconfig</code> command to obtain the IP address from the victim’s machine.

### S0335 - Carbon

Carbon can collect the IP address of the victims and other computers on the network using the commands: <code>ipconfig -all</code> <code>nbtstat -n</code>, and <code>nbtstat -s</code>.

### S0261 - Catchamas

Catchamas gathers the Mac address, IP address, and the network adapter information from the victim’s machine.

### S0572 - Caterpillar WebShell

Caterpillar WebShell can gather the IP address from the victim's machine using the IP config command.

### S0674 - CharmPower

CharmPower has the ability to use <code>ipconfig</code> to enumerate system network settings.

### S0667 - Chrommme

Chrommme can enumerate the IP address of a compromised host.

### S0660 - Clambling

Clambling can enumerate the IP address of a compromised machine.

### S0154 - Cobalt Strike

Cobalt Strike can determine the NetBios name and  the IP addresses of targets machines including domain controllers.

### S0244 - Comnie

Comnie uses <code>ipconfig /all</code> and <code>route PRINT</code> to identify network adapter and interface information.

### S0575 - Conti

Conti can retrieve the ARP cache from the local system by using the <code>GetIpNetTable()</code> API call and check to ensure IP addresses it connects to are for local, non-Internet, systems.

### S0488 - CrackMapExec

CrackMapExec can collect DNS information from the targeted system.

### S1024 - CreepySnail

CreepySnail can use `getmac` and `Get-NetIPAddress` to enumerate network settings.

### S0115 - Crimson

Crimson contains a command to collect the victim MAC address and LAN IP.

### S0625 - Cuba

Cuba can retrieve the ARP cache from the local system by using <code>GetIpNetTable</code>.

### S0687 - Cyclops Blink

Cyclops Blink can use the Linux API `if_nameindex` to gather network interface names.

### S1052 - DEADEYE

DEADEYE can discover the DNS domain name of a targeted system.

### S1159 - DUSTTRAP

DUSTTRAP can enumerate infected system network information.

### S0354 - Denis

Denis uses <code>ipconfig</code> to gather the IP address from the system.

### S0659 - Diavol

Diavol can enumerate victims' local and external IPs when registering with C2.

### S0567 - Dtrack

Dtrack can collect the host's IP addresses using the <code>ipconfig</code> command.

### S0038 - Duqu

The reconnaissance modules used with Duqu can collect information on network configuration.

### S0024 - Dyre

Dyre has the ability to identify network settings on a compromised host.

### S0605 - EKANS

EKANS can determine the domain of a compromised host.

### S0081 - Elise

Elise executes <code>ipconfig /all</code> after initial communication is made to the remote server.

### S0082 - Emissary

Emissary has the capability to execute the command <code>ipconfig /all</code>.

### S0363 - Empire

Empire can acquire network configuration information like DNS servers, public IP, and network proxies used by a host.

### S0091 - Epic

Epic uses the <code>nbtstat -n</code> and <code>nbtstat -s</code> commands on the victim’s machine.

### S0569 - Explosive

Explosive has collected the MAC address from the victim's machine.

### S0181 - FALLCHILL

FALLCHILL collects MAC address and local IP address information from the victim.

### S0267 - FELIXROOT

FELIXROOT collects information about the network including the IP address and DHCP server.

### S0512 - FatDuke

FatDuke can identify the MAC address on the target computer.

### S0171 - Felismus

Felismus collects the victim LAN IP address and sends it to the C2 server.

### S0696 - Flagpro

Flagpro has been used to execute the <code>ipconfig /all</code> command on a victim system.

### S1044 - FunnyDream

FunnyDream can parse the `ProxyServer` string in the Registry to discover http proxies.

### S0049 - GeminiDuke

GeminiDuke collects information on network settings and Internet proxy settings from the victim.

### S0588 - GoldMax

GoldMax retrieved a list of the system's network interface after execution.

### S1198 - Gomir

Gomir collects network information on infected systems such as listing interface names, MAC and IP addresses, and IPv6 addresses.

### S1138 - Gootloader

Gootloader can use an embedded script to check the IP address of potential victims visiting compromised websites.

### S0531 - Grandoreiro

Grandoreiro can determine the IP and physical location of the compromised host via IPinfo.

### S0237 - GravityRAT

GravityRAT collects the victim IP address, MAC address, as well as the victim account domain name.

### S0690 - Green Lambert

Green Lambert can obtain proxy information from a victim's machine using system environment variables.

### S0632 - GrimAgent

GrimAgent can enumerate the IP and domain of a target system.

### S1229 - Havoc

Havoc has a module for network enumeration including determining IP addresses.

### S1249 - HexEval Loader

HexEval Loader has leveraged server-side client configurations to identify the public IP of the victim host.

### S0431 - HotCroissant

HotCroissant has the ability to identify the IP address of the compromised machine.

### S0203 - Hydraq

Hydraq creates a backdoor through which remote attackers can retrieve IP addresses of compromised machines.

### S1022 - IceApple

The IceApple ifconfig module can iterate over all network interfaces on the host and retrieve the name, description, MAC address, DNS suffix, DNS servers, gateways, IPv4 addresses, and subnet masks.

### S0483 - IcedID

IcedID used the `ipconfig /all` command and a batch script to gather network information.

### S0604 - Industroyer

Industroyer’s 61850 payload component enumerates connected network adapters and their corresponding IP addresses.

### S0260 - InvisiMole

InvisiMole gathers information on the IP forwarding table, MAC address, configured proxy, and network SSID.

### S1245 - InvisibleFerret

InvisibleFerret has collected the local IP address, and external IP.

### S0015 - Ixeshe

Ixeshe enumerates the IP address, network proxy settings, and domain name from a victim's system.

### S1203 - J-magic

J-magic can compare the host and remote IPs to check if a received packet is from the infected machine.

### S0044 - JHUHUGIT

A JHUHUGIT variant gathers network interface card information.

### S0201 - JPIN

JPIN can obtain network information, including DNS, IP, and proxies.

### S0271 - KEYMARBLE

KEYMARBLE gathers the MAC address of the victim’s machine.

### S0356 - KONNI

KONNI can collect the IP address from the victim’s machine.

### S1075 - KOPILUWAK

KOPILUWAK can use Arp to discover a target's network configuration setttings.

### S0265 - Kazuar

Kazuar gathers information about network adapters.

### S0487 - Kessel

Kessel has collected the DNS address of the infected host.

### S1020 - Kevin

Kevin can collect the MAC address and other information from a victim machine using `ipconfig/all`.

### S0387 - KeyBoy

KeyBoy can determine the public or WAN IP address for the system.

### S0250 - Koadic

Koadic can retrieve the contents of the IP routing table as well as information about the Windows domain.

### S0641 - Kobalos

Kobalos can record the IP address of the target machine.

### S0236 - Kwampirs

Kwampirs collects network adapter and interface information by using the commands <code>ipconfig /all</code>, <code>arp -a</code> and <code>route print</code>. It also collects the system's MAC address with <code>getmac</code> and domain configuration with <code>net config workstation</code>.

### S1160 - Latrodectus

Latrodectus can discover the IP and MAC address of a targeted host.

### S0395 - LightNeuron

LightNeuron gathers information about network adapters using the Win32 API call <code>GetAdaptersInfo</code>.

### S0513 - LiteDuke

LiteDuke has the ability to discover the proxy configuration of Firefox and/or Opera.

### S0681 - Lizar

Lizar has retrieved network information from a compromised host, such as the MAC address.

### S0447 - Lokibot

Lokibot has the ability to discover the domain name of the infected host.

### S0451 - LoudMiner

LoudMiner used a script to gather the IP address of the infected machine before sending to the C2.

### S0532 - Lucifer

Lucifer can collect the IP address of a compromised host.

### S1143 - LunarLoader

LunarLoader can verify the targeted host's DNS name which is then used in the creation of a decyrption key.

### S1141 - LunarWeb

LunarWeb can use shell commands to discover network adapters and configuration.

### S1016 - MacMa

MacMa can collect IP addresses from a compromised host.

### S0409 - Machete

Machete collects the MAC address of the target computer and other network configuration information.

### S1060 - Mafalda

Mafalda can use the `GetAdaptersInfo` function to retrieve information about network adapters and the `GetIpNetTable` function to retrieve the IPv4 to physical network address mapping table.

### S1182 - MagicRAT

MagicRAT collects system network information using commands such as `ipconfig /all`.

### S1156 - Manjusaka

Manjusaka gathers information about current network connections, local and remote addresses associated with them, and associated processes.

### S1015 - Milan

Milan can run `C:\Windows\system32\cmd.exe /c cmd /c ipconfig /all 2>&1` to discover network settings.

### S0084 - Mis-Type

Mis-Type may create a file containing the results of the command <code>cmd.exe /c ipconfig /all</code>.

### S0149 - MoonWind

MoonWind obtains the victim IP address.

### S0284 - More_eggs

More_eggs has the capability to gather the IP address from the victim's machine.

### S0256 - Mosquito

Mosquito uses the <code>ipconfig</code> command.

### S0590 - NBTscan

NBTscan can be used to collect MAC addresses.

### S0198 - NETWIRE

NETWIRE can collect the IP address of a compromised host.

### S1106 - NGLite

NGLite identifies the victim system MAC and IPv4 addresses and uses these to establish a victim identifier.

### S0353 - NOKKI

NOKKI can gather information on the victim IP address.

### S0205 - Naid

Naid collects the domain name from a compromised host.

### S0228 - NanHaiShu

NanHaiShu can gather information about the victim proxy server.

### S0336 - NanoCore

NanoCore gathers the IP address from the victim’s machine.

### S0691 - Neoichor

Neoichor can gather the IP address from an infected host.

### S1147 - Nightdoor

Nightdoor gathers information on victim system network configuration such as MAC addresses.

### S1100 - Ninja

Ninja can enumerate the IP address on compromised systems.

### S0359 - Nltest

Nltest may be used to enumerate the parent domain of a local machine using <code>/parentdomain</code>.

### S0165 - OSInfo

OSInfo discovers the current domain information.

### S0352 - OSX_OCEANLOTUS.D

OSX_OCEANLOTUS.D can collect the network interface MAC address on the infected host.

### S0346 - OceanSalt

OceanSalt can collect the victim’s IP address.

### S0340 - Octopus

Octopus can collect the host IP address from the victim’s machine.

### S0439 - Okrum

Okrum can collect network information, including the host IP address, DNS, and proxy information.

### S0365 - Olympic Destroyer

Olympic Destroyer uses API calls to enumerate the infected system's ARP table.

### S0229 - Orz

Orz can gather victim proxy information.

### S0254 - PLAINTEE

PLAINTEE uses the <code>ipconfig /all</code> command to gather the victim’s IP address.

### S0223 - POWERSTATS

POWERSTATS can retrieve IP, network adapter configuration information, and domain from compromised hosts.

### S0184 - POWRUNER

POWRUNER may collect network configuration data by running <code>ipconfig /all</code> on a victim.

### S1228 - PUBLOAD

PUBLOAD has obtained information about local networks through the `ipconfig /all` command.

### S0556 - Pay2Key

Pay2Key can identify the IP and MAC addresses of the compromised host.

### S1050 - PcShare

PcShare can obtain the proxy settings of a compromised machine using `InternetQueryOptionA` and its IP address by running `nslookup myip.opendns.comresolver1.opendns.com\r\n`.

### S0587 - Penquin

Penquin can report the IP of the compromised host to attacker controlled infrastructure.

### S1145 - Pikabot

Pikabot gathers victim network information through commands such as <code>ipconfig</code> and <code>ipconfig /all</code>.

### S1031 - PingPull

PingPull can retrieve the IP address of a compromised host.

### S0501 - PipeMon

PipeMon can collect and send the local IP address, RDP information, and the network adapter physical address as a part of its C2 beacon.

### S0124 - Pisloader

Pisloader has a command to collect the victim's IP address.

### S0013 - PlugX

PlugX has captured victim IP address details of the targeted machine.

### S0378 - PoshC2

PoshC2 can enumerate network adapter information.

### S0139 - PowerDuke

PowerDuke has a command to get the victim's domain and NetBIOS name.

### S0441 - PowerShower

PowerShower has the ability to identify the current Windows domain of the infected host.

### S0113 - Prikormka

A module in Prikormka collects information from the victim about its IP addresses and MAC addresses.

### S0238 - Proxysvc

Proxysvc collects the network adapter information and domain/username information based on current remote sessions.

### S0192 - Pupy

Pupy has built in commands to identify a host’s IP address and find out other network configuration settings by viewing connected sessions.

### S0583 - Pysa

Pysa can perform network reconnaissance using the Advanced IP Scanner tool.

### S0269 - QUADAGENT

QUADAGENT gathers the current domain the victim system belongs to.

### S1076 - QUIETCANARY

QUIETCANARY can identify the default proxy setting on a compromised host.

### S0650 - QakBot

QakBot can use <code>net config workstation</code>, <code>arp -a</code>, `nslookup`, and <code>ipconfig /all</code> to gather network configuration information.

### S1242 - Qilin

Qilin can accept a command line argument identifying specific IPs.

### S0262 - QuasarRAT

QuasarRAT has the ability to enumerate the Wide Area Network (WAN) IP through requests to ip-api[.]com, freegeoip[.]net, or api[.]ipify[.]org observed with user-agent string `Mozilla/5.0 (Windows NT 6.3; rv:48.0) Gecko/20100101 Firefox/48.0`.

### S0241 - RATANKBA

RATANKBA gathers the victim’s IP address via the <code>ipconfig -all</code> command.

### S0458 - Ramsay

Ramsay can use ipconfig and Arp to collect network configuration information, including routing information and ARP tables.

### S0172 - Reaver

Reaver collects the victim's IP address.

### S0153 - RedLeaves

RedLeaves can obtain information about network parameters.

### S1240 - RedLine Stealer

RedLine Stealer can enumeate information about victims’ systems including IP addresses.

### S0125 - Remsec

Remsec can obtain information about network configuration, including the routing table, ARP cache, and DNS cache.

### S0379 - Revenge RAT

Revenge RAT collects the IP address and MAC address from the system.

### S0433 - Rifdoor

Rifdoor has the ability to identify the IP address of the compromised host.

### S0448 - Rising Sun

Rising Sun can detect network adapter and IP address information.

### S0270 - RogueRobin

RogueRobin gathers the IP address and domain from the victim’s machine.

### S1073 - Royal

Royal can enumerate IP addresses using `GetIpAddrTable`.

### S0446 - Ryuk

Ryuk has called <code>GetIpNetTable</code> in attempt to identify all mounted drives and hosts that have Address Resolution Protocol (ARP) entries.

### S0085 - S-Type

S-Type has used `ipconfig /all` on a compromised host.

### S0461 - SDBbot

SDBbot has the ability to determine the domain name and whether a proxy is configured on a compromised host.

### S0450 - SHARPSTATS

SHARPSTATS has the ability to identify the domain of the compromised host.

### S1037 - STARWHALE

STARWHALE has the ability to collect the IP address of an infected host.

### S0559 - SUNBURST

SUNBURST collected all network interface MAC addresses that are up and not loopback devices, as well as IP address, DHCP configuration, and domain information.

### S1210 - Sagerunex

Sagerunex will gather system information such as MAC and IP addresses.

### S1018 - Saint Bot

Saint Bot can collect the IP address of a victim machine.

### S1085 - Sardonic

Sardonic has the ability to execute the `ipconfig` command.

### S0596 - ShadowPad

ShadowPad has collected the domain name of the victim system.

### S0140 - Shamoon

Shamoon obtains the target's IP address and local network segment.

### S0445 - ShimRatReporter

ShimRatReporter gathered the local proxy, domain, IP, routing tables, mac address, gateway, DNS servers, and DHCP status information from an infected host.

### S1178 - ShrinkLocker

ShrinkLocker captures the IP address of the victim system and sends this to the attacker following encryption.

### S0589 - Sibot

Sibot checked if the compromised system is configured to use proxies.

### S0610 - SideTwist

SideTwist has the ability to collect the domain name on a compromised host.

### S0633 - Sliver

Sliver has the ability to gather network configuration information.

### S1035 - Small Sieve

Small Sieve can obtain the IP address of a victim host.

### S1124 - SocGholish

SocGholish has the ability to enumerate the domain name of a victim, as well as if the host is a member of an Active Directory domain.

### S0516 - SoreFang

SoreFang can collect the TCP/IP, DNS, DHCP, and network adapter configuration on a compromised host via <code>ipconfig.exe /all</code>.

### S0374 - SpeakUp

SpeakUp uses the <code>ifconfig -a</code> command.

### S0646 - SpicyOmelette

SpicyOmelette can identify the IP of a compromised system.

### S1030 - Squirrelwaffle

Squirrelwaffle has collected the victim’s external IP address.

### S0491 - StrongPity

StrongPity can identify the IP address of a compromised host.

### S0603 - Stuxnet

Stuxnet collects the IP address of a compromised system.

### S0018 - Sykipot

Sykipot may use <code>ipconfig /all</code> to gather system network configuration details.

### S0060 - Sys10

Sys10 collects the local IP address of the victim and sends it to the C2.

### S0663 - SysUpdate

SysUpdate can collected the IP address and domain name of a compromised host.

### S0098 - T9000

T9000 gathers and beacons the MAC and IP addresses during installation.

### S0436 - TSCookie

TSCookie has the ability to identify the IP of the infected host.

### S0011 - Taidoor

Taidoor has collected the MAC address of a compromised host; it can also use <code>GetAdaptersInfo</code> to identify network adapters.

### S0467 - TajMahal

TajMahal has the ability to identify the MAC address on an infected host.

### S0678 - Torisma

Torisma can collect the local MAC address using `GetAdaptersInfo` as well as the system's IP address.

### S0266 - TrickBot

TrickBot obtains the IP address, location, and other relevant network information from the victim’s machine.

### S0094 - Trojan.Karagany

Trojan.Karagany can gather information on the network configuration of a compromised host.

### S1196 - Troll Stealer

Troll Stealer collects the MAC address of victim devices.

### S0647 - Turian

Turian can retrieve the internal IP address of a compromised host.

### S0275 - UPPERCUT

UPPERCUT has the capability to gather the victim's proxy information.

### S0452 - USBferry

USBferry can detect the infected machine's network topology using <code>ipconfig</code> and <code>arp</code>.

### S0130 - Unknown Logger

Unknown Logger can obtain information about the victim's IP address.

### S0257 - VERMIN

VERMIN gathers the local IP address.

### S0476 - Valak

Valak has the ability to identify the domain and the MAC and IP addresses of an infected machine.

### S0180 - Volgmer

Volgmer can gather the IP address from the victim's machine.

### S0366 - WannaCry

WannaCry will attempt to determine the local network segment it is a part of.

### S0515 - WellMail

WellMail can identify the IP address of the victim system.

### S0514 - WellMess

WellMess can identify the IP address and user domain on the target machine.

### S1065 - Woody RAT

Woody RAT can retrieve network interface and proxy information.

### S1248 - XORIndex Loader

XORIndex Loader has leveraged webservices to identify the public IP of the victim host.

### S0341 - Xbash

Xbash can collect IP addresses and local intranet information from a victim’s machine.

### S0251 - Zebrocy

Zebrocy runs the <code>ipconfig /all</code> command.

### S0230 - ZeroT

ZeroT gathers the victim's IP address and domain information, and then sends it to its C2 server.

### S1204 - cd00r

cd00r can discover the IP for the network interface on the compromised device.

### S0472 - down_new

down_new has the ability to identify the MAC address of a compromised host.

### S0278 - iKitten

iKitten will look for the current IP address.

### S0101 - ifconfig

ifconfig can be used to display adapter configuration on Unix systems, including information for TCP/IP, DNS, and DHCP.

### S0100 - ipconfig

ipconfig can be used to display adapter configuration on Windows systems, including information for TCP/IP, DNS, and DHCP.

### S0283 - jRAT

jRAT can gather victim internal and external IPs.

### S0102 - nbtstat

nbtstat can be used to discover local NetBIOS domain names.

### S0103 - route

route can be used to discover routing configuration information.

### S0653 - xCaon

xCaon has used the GetAdaptersInfo() API call to get the victim's MAC address.

### S0248 - yty

yty runs <code>ipconfig /all</code> and collects the domain name.

### S0350 - zwShell

zwShell can obtain the victim IP address.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0015 - C0015

During C0015, the threat actors used code to obtain the external public-facing IPv4 address of the compromised host.

### C0017 - C0017

During C0017, APT41 used `cmd.exe /c ping %userdomain%` for discovery.

### C0018 - C0018

During C0018, the threat actors ran `nslookup` and Advanced IP Scanner on the target network.

### C0001 - Frankenstein

During Frankenstein, the threat actors used Empire to find the public IP address of a compromised system.

### C0007 - FunnyDream

During FunnyDream, the threat actors used ipconfig for discovery on remote systems.

### C0035 - KV Botnet Activity

KV Botnet Activity gathers victim IP information during initial installation stages.

### C0012 - Operation CuckooBees

During Operation CuckooBees, the threat actors used `ipconfig`, `nbtstat`, `tracert`, `route print`, and `cat /etc/hosts` commands.

### C0014 - Operation Wocao

During Operation Wocao, threat actors discovered the local network configuration with `ipconfig`.

### C0056 - RedPenguin

During RedPenguin, UNC3886 leveraged JunoOS CLI queries to obtain the interface index which contains system and network details.

### C0045 - ShadowRay

During ShadowRay, threat actors invoked DNS queries from targeted machines to identify their IP addresses.
