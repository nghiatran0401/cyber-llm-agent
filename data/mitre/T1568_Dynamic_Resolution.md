# T1568 - Dynamic Resolution

**Tactic:** Command and Control
**Platforms:** ESXi, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1568

## Description

Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations. This may be achieved by using malware that shares a common algorithm with the infrastructure the adversary uses to receive the malware's communications. These calculations can be used to dynamically adjust parameters such as the domain name, IP address, or port number the malware uses for command and control.

Adversaries may use dynamic resolution for the purpose of Fallback Channels. When contact is lost with the primary command and control server malware may employ dynamic resolution as a means to reestablishing command and control.

## Detection

### Detection Analytics

**Analytic 0109**

Correlate high-frequency or anomalous DNS query activity with processes that do not normally generate network requests (e.g., Office apps, system utilities). Detect pseudo-random or high-entropy domain lookups indicative of domain generation algorithms (DGAs).

**Analytic 0110**

Monitor /var/log/audit/audit.log and DNS resolver logs for repeated failed lookups or connections to high-entropy domain names. Correlate suspicious DNS queries with process lineage (e.g., Python, bash, or unusual system daemons).

**Analytic 0111**

Inspect unified logs for anomalous DNS resolutions triggered by non-network applications. Flag repeated connections to newly registered or algorithmically generated domains. Correlate with endpoint process telemetry.

**Analytic 0112**

Monitor esxcli and syslog records for DNS resolver changes or repeated queries to unusual external domains by management agents. Detect unauthorized changes to VM or host network settings that redirect DNS lookups.


## Mitigations

### M1031 - Network Intrusion Prevention

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Malware researchers can reverse engineer malware variants that use dynamic resolution and determine future C2 infrastructure that the malware will attempt to contact, but this is a time and resource intensive effort.

### M1021 - Restrict Web-Based Content

In some cases a local DNS sinkhole may be used to help prevent behaviors associated with dynamic resolution.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1087 - AsyncRAT

AsyncRAT can be configured to use dynamic DNS.

### S0268 - Bisonal

Bisonal has used a dynamic DNS service for C2.

### S0666 - Gelsemium

Gelsemium can use dynamic DNS domain names in C2.

### S0449 - Maze

Maze has forged POST strings with a random choice from a list of possibilities including "forum", "php", "view", etc. while making connection with the C2, hindering detection efforts.

### S0034 - NETEAGLE

NETEAGLE can use HTTP to download resources that contain an IP address and port number pair to connect to for C2.

### S0148 - RTM

RTM has resolved Pony C2 server IP addresses by either converting Bitcoin blockchain transaction data to specific octets, or accessing IP addresses directly within the Namecoin blockchain.

### S0559 - SUNBURST

SUNBURST dynamically resolved C2 infrastructure for randomly-generated subdomains within a parent domain.

### S0671 - Tomiris

Tomiris has connected to a signalization server that provides a URL and port, and then Tomiris sends a GET request to that URL to establish C2.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0026 - C0026

During C0026, the threat actors re-registered a ClouDNS dynamic DNS subdomain which was previously used by ANDROMEDA.

### C0043 - Indian Critical Infrastructure Intrusions

During Indian Critical Infrastructure Intrusions, RedEcho used dynamic DNS domains associated with malicious infrastructure.

### C0002 - Night Dragon

During Night Dragon, threat actors used dynamic DNS services for C2.

### C0016 - Operation Dust Storm

For Operation Dust Storm, the threat actors used dynamic DNS domains from a variety of free providers, including No-IP, Oray, and 3322.

### C0005 - Operation Spalax

For Operation Spalax, the threat actors used dynamic DNS services, including Duck DNS and DNS Exit, as part of their C2 infrastructure.

### C0024 - SolarWinds Compromise

During the SolarWinds Compromise, APT29 used dynamic DNS resolution to construct and resolve to randomly-generated subdomains for C2.
