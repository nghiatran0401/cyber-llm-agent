# T1021 - Remote Services

**Tactic:** Lateral Movement
**Platforms:** ESXi, IaaS, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1021

## Description

Adversaries may use Valid Accounts to log into a service that accepts remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user.

In an enterprise environment, servers and workstations can be organized into domains. Domains provide centralized identity management, allowing users to login using one set of credentials across the entire network. If an adversary is able to obtain a set of valid domain credentials, they could login to many different machines using remote access protocols such as secure shell (SSH) or remote desktop protocol (RDP). They could also login to accessible SaaS or IaaS services, such as those that federate their identities to the domain, or management platforms for internal virtualization environments such as VMware vCenter. 

Legitimate applications (such as Software Deployment Tools and other administrative programs) may utilize Remote Services to access remote hosts. For example, Apple Remote Desktop (ARD) on macOS is native software used for remote management. ARD leverages a blend of protocols, including VNC to send the screen and control buffers and SSH for secure file transfer. Adversaries can abuse applications such as ARD to gain remote code execution and perform lateral movement. In versions of macOS prior to 10.14, an adversary can escalate an SSH session to an ARD session which enables an adversary to accept TCC (Transparency, Consent, and Control) prompts without user interaction and gain access to data.

## Detection

### Detection Analytics

**Analytic 0750**

Logon via RDP or WMI by a user account followed by uncommon command execution, file manipulation, or lateral network connections.

**Analytic 0751**

SSH session from new source IP followed by interactive shell or privilege escalation (e.g., sudo, su) and outbound lateral connection.

**Analytic 0752**

Remote login via ARD or SSH followed by screensharingd process activity or modification of TCC-protected files.

**Analytic 0753**

Use of cloud-based bastion or VM console session followed by commands that initiate outbound SSH or RDP sessions from the cloud instance to other environments.

**Analytic 0754**

vSphere API logins (vimService) or SSH to ESXi host followed by unauthorized shell commands or lateral remote logins from the ESXi host.


## Mitigations

### M1047 - Audit

Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses.

### M1042 - Disable or Remove Feature or Program

If remote services, such as the ability to make direct connections to cloud virtual machines, are not required, disable these connection types where feasible. On ESXi servers, consider enabling lockdown mode, which disables direct access to an ESXi host and requires that the host be managed remotely using vCenter.

### M1035 - Limit Access to Resource Over Network

Prevent unnecessary remote access to file shares, hypervisors, sensitive systems, etc. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc.

### M1032 - Multi-factor Authentication

Use multi-factor authentication on remote service logons where possible.

### M1027 - Password Policies

Do not reuse local administrator account passwords across systems. Ensure password complexity and uniqueness such that the passwords cannot be cracked or guessed.

### M1018 - User Account Management

Limit the accounts that may use remote services. Limit the permissions for accounts that are at higher risk of compromise; for example, configure SSH so users can only run specific programs.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1063 - Brute Ratel C4

Brute Ratel C4 has the ability to use RPC for lateral movement.

### S0437 - Kivars

Kivars has the ability to remotely trigger keyboard input and mouse clicks.

### S1016 - MacMa

MacMa can manage remote screen sessions.

### S0603 - Stuxnet

Stuxnet can propagate via peer-to-peer communication and updates using RPC.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
