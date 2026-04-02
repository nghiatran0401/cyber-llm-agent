# T1219 - Remote Access Tools

**Tactic:** Command and Control
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1219

## Description

An adversary may use legitimate remote access tools to establish an interactive command and control channel within a network. Remote access tools create a session between two trusted hosts through a graphical interface, a command line interaction, a protocol tunnel via development or management software, or hardware-level access such as KVM (Keyboard, Video, Mouse) over IP solutions. Desktop support software (usually graphical interface) and remote management software (typically command line interface) allow a user to control a computer remotely as if they are a local user inheriting the user or software permissions. This software is commonly used for troubleshooting, software installation, and system management. Adversaries may similarly abuse response features included in EDR and other defensive tools that enable remote access.

Remote access tools may be installed and used post-compromise as an alternate communications channel for redundant access or to establish an interactive remote desktop session with the target system. It may also be used as a malware component to establish a reverse connection or back-connect to a service or adversary-controlled system.

Installation of many remote access tools may also include persistence (e.g., the software's installation routine creates a Windows Service). Remote access modules/features may also exist as part of otherwise existing software (e.g., Google Chrome’s Remote Desktop).

## Detection

### Detection Analytics

**Analytic 1366**

Chain of remote access tool behavior: (1) initial execution of remote-control/assist agent or GUI under user context; (2) persistence via service or autorun; (3) long-lived outbound connection/tunnel to external infrastructure; (4) interactive control signals such as shell or file-manager child processes spawned by the RAT parent.

**Analytic 1367**

Sequence of RAT agent execution, systemd persistence, and long-lived external egress; optional interactive shells spawned from the agent.

**Analytic 1368**

Electron/GUI or headless RAT execution followed by LaunchAgent/Daemon persistence and persistent external connections; interactive children (osascript/sh/curl) spawned by parent.


## Mitigations

### M1042 - Disable or Remove Feature or Program

Consider disabling unnecessary remote connection functionality, including both unapproved software installations and specific features built into supported applications.

### M1038 - Execution Prevention

Use application control to mitigate installation and use of unapproved software that can be used for remote access.

### M1037 - Filter Network Traffic

Properly configure firewalls, application firewalls, and proxies to limit outgoing traffic to sites and services used by remote access software.

### M1034 - Limit Hardware Installation

Block the use of IP-based KVM devices within the network if they are not required.

### M1031 - Network Intrusion Prevention

Network intrusion detection and prevention systems that use network signatures may be able to prevent traffic to remote access services.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0030 - Carbanak

Carbanak has a plugin for VNC and Ammyy Admin Tool.

### S0384 - Dridex

Dridex contains a module for VNC.

### S0554 - Egregor

Egregor has checked for the LogMein event log in an attempt to encrypt files in remote machines.

### S0601 - Hildegard

Hildegard has established tmate sessions for C2 communications.

### S1245 - InvisibleFerret

InvisibleFerret has utilized remote access software including AnyDesk client through the “adc” module. InvisibleFerret has also downloaded the AnyDesk client should it not already exist on the compromised host by searching for `C:/Program Files(x86)/AnyDesk/AnyDesk.exe`.

### S0148 - RTM

RTM has the capability to download a VNC module from command and control (C2).

### S0266 - TrickBot

TrickBot uses vncDll module to remote control the victim machine.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0002 - Night Dragon

During Night Dragon, threat actors used several remote administration tools as persistent infiltration channels.
