# T1505 - Server Software Component

**Tactic:** Persistence
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1505

## Description

Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems. Enterprise server applications may include features that allow developers to write and install software or scripts to extend the functionality of the main application. Adversaries may install malicious components to extend and abuse server applications.

## Detection

### Detection Analytics

**Analytic 1507**

Installation of malicious IIS/Apache/SQL server modules that later execute command-line interpreters or establish outbound connections.

**Analytic 1508**

Abuse of extensible server modules (e.g., Apache, Nginx, Tomcat) to load rogue plugins that initiate bash, connect to C2, or spawn reverse shells.

**Analytic 1509**

Malicious use of webserver plugins (e.g., for nginx, PHP, Node.js) that execute AppleScript or open network sockets.

**Analytic 1510**

Use of ESXi web interface plugins or vSphere extensions to embed persistent malicious scripts or services.


## Mitigations

### M1047 - Audit

Regularly check component software on critical services that adversaries may target for persistence to verify the integrity of the systems and identify if unexpected changes have been made.

### M1046 - Boot Integrity

Enabling secure boot allows validation of software and drivers during initial system boot.

### M1045 - Code Signing

Ensure all application component binaries are signed by the correct application developers.

### M1042 - Disable or Remove Feature or Program

Consider disabling software components from servers when possible to prevent abuse by adversaries.

### M1026 - Privileged Account Management

Do not allow administrator accounts that have permissions to add component software on these services to be used for day-to-day operations that may expose them to potential adversaries on unprivileged systems.

### M1024 - Restrict Registry Permissions

Consider using Group Policy to configure and block modifications to service and other critical server parameters in the Registry.

### M1018 - User Account Management

Enforce the principle of least privilege by limiting privileges of user accounts so only authorized accounts can modify and/or add server software components.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
