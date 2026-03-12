# T1563 - Remote Service Session Hijacking

**Tactic:** Lateral Movement
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1563

## Description

Adversaries may take control of preexisting sessions with remote services to move laterally in an environment. Users may use valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and RDP. When a user logs into a service, a session will be established that will allow them to maintain a continuous interaction with that service.

Adversaries may commandeer these sessions to carry out actions on remote systems. Remote Service Session Hijacking differs from use of Remote Services because it hijacks an existing session rather than creating a new session using Valid Accounts.

## Detection

### Detection Analytics

**Analytic 0216**

Detection of anomalous RDP or remote service session activity where a logon session is hijacked rather than newly created. Indicators include mismatched user credentials vs. active session tokens, service session takeovers without corresponding successful logon events, or RDP shadowing activity without user consent.

**Analytic 0217**

Detection of SSH/Telnet session hijacking via discrepancies between authentication logs and active session tables. Adversary behavior includes reusing or stealing active PTY sessions, attaching to screen/tmux, or issuing commands without corresponding login events.

**Analytic 0218**

Detection of hijacked VNC or SSH sessions on macOS where adversaries take over an existing session rather than authenticating directly. Indicators include process execution from active sessions without new logon events, manipulation of TTY sessions, or anomalous network activity tied to dormant sessions.


## Mitigations

### M1042 - Disable or Remove Feature or Program

Disable the remote service (ex: SSH, RDP, etc.) if it is unnecessary.

### M1030 - Network Segmentation

Enable firewall rules to block unnecessary traffic between network security zones within a network.

### M1027 - Password Policies

Set and enforce secure password policies for accounts.

### M1026 - Privileged Account Management

Do not allow remote access to services as a privileged account unless necessary.

### M1018 - User Account Management

Limit remote user permissions if remote access is necessary.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
