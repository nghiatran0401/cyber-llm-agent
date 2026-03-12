# T1072 - Software Deployment Tools

**Tactic:** Execution, Lateral Movement
**Platforms:** Linux, Network Devices, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1072

## Description

Adversaries may gain access to and use centralized software suites installed within an enterprise to execute commands and move laterally through the network. Configuration management and software deployment applications may be used in an enterprise network or cloud environment for routine administration purposes. These systems may also be integrated into CI/CD pipelines. Examples of such solutions include: SCCM, HBSS, Altiris, AWS Systems Manager, Microsoft Intune, Azure Arc, and GCP Deployment Manager.  

Access to network-wide or enterprise-wide endpoint management software may enable an adversary to achieve remote code execution on all connected systems. The access may be used to laterally move to other systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints.

SaaS-based configuration management services may allow for broad Cloud Administration Command on cloud-hosted instances, as well as the execution of arbitrary commands on on-premises endpoints. For example, Microsoft Configuration Manager allows Global or Intune Administrators to run scripts as SYSTEM on on-premises devices joined to Entra ID. Such services may also utilize Web Protocols to communicate back to adversary owned infrastructure.

Network infrastructure devices may also have configuration management tools that can be similarly abused by adversaries.

The permissions required for this action vary by system configuration; local credentials may be sufficient with direct access to the third-party system, or specific domain credentials may be required. However, the system may require an administrative account to log in or to access specific functionality.

## Detection

### Detection Analytics

**Analytic 0623**

Detects SCCM, Intune, or remote push execution spawning scripts or binaries from SYSTEM context or unusual consoles (e.g., cmtrace.exe launching PowerShell or cmd.exe).

**Analytic 0624**

Detects remote scripts or binaries deployed via Puppet, Chef, Ansible, or shell scripts from orchestration servers executing outside maintenance windows or in unmanaged nodes.

**Analytic 0625**

Detects script or binary execution initiated via JAMF, Munki, or custom MDM agents outside of baseline, or JAMF launching new Terminal or osascript processes from remote command payloads.

**Analytic 0626**

Detects cloud-native software deployment or management (e.g., SSM Run Command, Intune) initiating script execution on endpoints outside expected org IDs, admin groups, or maintenance windows.

**Analytic 0627**

Detects central router or switch config management tools (e.g., FortiManager, Cisco Prime) triggering device reboots or config pushes using abnormal accounts or IPs.


## Mitigations

### M1015 - Active Directory Configuration

Ensure proper system and access isolation for critical network systems through use of group policy.

### M1033 - Limit Software Installation

Restrict the use of third-party software suites installed within an enterprise network.

### M1032 - Multi-factor Authentication

Ensure proper system and access isolation for critical network systems through use of multi-factor authentication.

### M1030 - Network Segmentation

Ensure proper system isolation for critical network systems through use of firewalls.

### M1027 - Password Policies

Verify that account credentials that may be used to access deployment systems are unique and not used throughout the enterprise network.

### M1026 - Privileged Account Management

Grant access to application deployment systems only to a limited number of authorized administrators.

### M1029 - Remote Data Storage

If the application deployment system can be configured to deploy only signed binaries, then ensure that the trusted signing certificates are not co-located with the application deployment system and are instead located on a system that cannot be accessed remotely or to which remote access is tightly controlled.

### M1051 - Update Software

Patch deployment systems regularly to prevent potential remote access through Exploitation for Privilege Escalation.

### M1018 - User Account Management

Ensure that any accounts used by third-party providers to access these systems are traceable to the third-party and are not used throughout the network or used by other third-party providers in the same environment. Ensure there are regular reviews of accounts provisioned to these systems to verify continued business need, and ensure there is governance to trace de-provisioning of access that is no longer required. Ensure proper system and access isolation for critical network systems through use of account privilege separation.

### M1017 - User Training

Have a strict approval policy for use of deployment systems.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0041 - Wiper

It is believed that a patch management system for an anti-virus product commonly installed among targeted companies was used to distribute the Wiper malware.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0018 - C0018

During C0018, the threat actors used PDQ Deploy to move AvosLocker and tools across the network.
