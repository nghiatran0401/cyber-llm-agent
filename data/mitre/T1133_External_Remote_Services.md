# T1133 - External Remote Services

**Tactic:** Initial Access, Persistence
**Platforms:** Containers, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1133

## Description

Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as Windows Remote Management and VNC can also be used externally.

Access to Valid Accounts to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network. Access to remote services may be used as a redundant or persistent access mechanism during an operation.

Access may also be gained through an exposed service that doesn’t require authentication. In containerized environments, this may include an exposed Docker API, Kubernetes API server, kubelet, or web application such as the Kubernetes dashboard.

Adversaries may also establish persistence on network by configuring a Tor hidden service on a compromised system. Adversaries may utilize the tool `ShadowLink` to facilitate the installation and configuration of the Tor hidden service. Tor hidden service is then accessible via the Tor network because `ShadowLink` sets up a .onion address on the compromised system. `ShadowLink` may be used to forward any inbound connections to RDP, allowing the adversaries to have remote access. Adversaries may get `ShadowLink` to persist on a system by masquerading it as an MS Defender application.

## Detection

### Detection Analytics

**Analytic 1004**

Unusual or unauthorized external remote access attempts (e.g., RDP, VPN, Citrix) → repeated failed logins followed by a successful session from uncommon geolocations or outside business hours → subsequent internal lateral movement or data exfiltration activities.

**Analytic 1005**

Repeated SSH, VPN, or RDP gateway authentication attempts from external IPs → subsequent successful logon → remote shell or lateral movement activity (e.g., scp/sftp).

**Analytic 1006**

Unexpected inbound or outbound VNC/SSH/Screen Sharing connections from external sources → repeated failed logins followed by success → remote interactive sessions or abnormal file transfers.

**Analytic 1007**

Connections to exposed container services (e.g., Docker API, Kubernetes API server) from unauthorized external IPs → abnormal container creation/start → lateral activity within cluster nodes.


## Mitigations

### M1042 - Disable or Remove Feature or Program

Disable or block remotely available services that may be unnecessary.

### M1035 - Limit Access to Resource Over Network

Limit access to remote services through centrally managed concentrators such as VPNs and other managed remote access systems.

### M1032 - Multi-factor Authentication

Use strong two-factor or multi-factor authentication for remote service accounts to mitigate an adversary's ability to leverage stolen credentials, but be aware of Multi-Factor Authentication Interception techniques for some two-factor authentication implementations.

### M1030 - Network Segmentation

Deny direct remote access to internal systems through the use of network proxies, gateways, and firewalls.

### M1021 - Restrict Web-Based Content

Restrict all traffic to and from public Tor nodes.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0600 - Doki

Doki was executed through an open Docker daemon API port.

### S0601 - Hildegard

Hildegard was executed through an unsecure kubelet that allowed anonymous access to the victim environment.

### S0599 - Kinsing

Kinsing was executed in an Ubuntu container deployed via an open Docker daemon API.

### S0362 - Linux Rabbit

Linux Rabbit attempts to gain access to the server via SSH.

### S1060 - Mafalda

Mafalda can establish an SSH connection from a compromised host to a server.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0028 - 2015 Ukraine Electric Power Attack

During the 2015 Ukraine Electric Power Attack, Sandworm Team installed a modified Dropbear SSH client as the backdoor to target systems.

### C0046 - ArcaneDoor

ArcaneDoor used WebVPN sessions commonly associated with Clientless SSLVPN services to communicate to compromised devices.

### C0027 - C0027

During C0027, Scattered Spider used Citrix and VPNs to persist in compromised environments.

### C0032 - C0032

During the C0032 campaign, TEMP.Veles used VPN access to persist in the victim environment.

### C0004 - CostaRicto

During CostaRicto, the threat actors set up remote tunneling using an SSH tool to maintain access to a compromised environment.

### C0002 - Night Dragon

During Night Dragon, threat actors used compromised VPN accounts to gain access to victim systems.

### C0012 - Operation CuckooBees

During Operation CuckooBees, the threat actors enabled WinRM over HTTP/HTTPS as a backup persistence mechanism using the following command: `cscript //nologo "C:\Windows\System32\winrm.vbs" set winrm/config/service@{EnableCompatibilityHttpsListener="true"}`.

### C0014 - Operation Wocao

During Operation Wocao, threat actors used stolen credentials to connect to the victim's network via VPN.

### C0024 - SolarWinds Compromise

For the SolarWinds Compromise, APT29 used compromised identities to access networks via SSH, VPNs, and other remote access tools.
