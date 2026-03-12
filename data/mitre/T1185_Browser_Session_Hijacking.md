# T1185 - Browser Session Hijacking

**Tactic:** Collection
**Platforms:** Windows
**Reference:** https://attack.mitre.org/techniques/T1185

## Description

Adversaries may take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify user-behaviors, and intercept information as part of various browser session hijacking techniques.

A specific example is when an adversary injects software into a browser that allows them to inherit cookies, HTTP sessions, and SSL client certificates of a user then use the browser as a way to pivot into an authenticated intranet. Executing browser-based behaviors such as pivoting may require specific process permissions, such as <code>SeDebugPrivilege</code> and/or high-integrity/administrator rights.

Another example involves pivoting browser traffic from the adversary's browser through the user's browser by setting up a proxy which will redirect web traffic. This does not alter the user's traffic in any way, and the proxy connection can be severed as soon as the browser is closed. The adversary assumes the security context of whichever browser process the proxy is injected into. Browsers typically create a new process for each tab that is opened and permissions and certificates are separated accordingly. With these permissions, an adversary could potentially browse to any resource on an intranet, such as Sharepoint or webmail, that is accessible through the browser and which the browser has sufficient permissions. Browser pivoting may also bypass security provided by 2-factor authentication.

## Detection

### Detection Analytics

**Analytic 1398**

Adversary gains high integrity or special privileges (e.g., SeDebugPrivilege), locates a running browser process, opens it with write/inject rights, and modifies it (e.g., CreateRemoteThread / DLL load) to inherit cookies/tokens or establish a browser pivot. Optional step: create a new logon session or use explicit credentials, then drive the victim browser to intranet resources.


## Mitigations

### M1018 - User Account Management

Since browser pivoting requires a high integrity process to launch from, restricting user permissions and addressing Privilege Escalation and Bypass User Account Control opportunities can limit the exposure to this technique.

### M1017 - User Training

Close all browser sessions regularly and when they are no longer needed.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0331 - Agent Tesla

Agent Tesla has the ability to use form-grabbing to extract data from web data forms.

### S0484 - Carberp

Carberp has captured credentials when a user performs login through a SSL session.

### S0631 - Chaes

Chaes has used the Puppeteer module to hook and monitor the Chrome web browser to collect user information from infected hosts.

### S0154 - Cobalt Strike

Cobalt Strike can perform browser pivoting and inject into a user's browser to inherit cookies, authenticated HTTP sessions, and client SSL certificates.

### S0384 - Dridex

Dridex can perform browser attacks via web injects to steal information such as credentials, certificates, and cookies.

### S0531 - Grandoreiro

Grandoreiro can monitor browser activity for online banking actions and display full-screen overlay images to block user access to the intended site or present additional data fields.

### S0483 - IcedID

IcedID has used web injection attacks to redirect victims to spoofed sites designed to harvest banking and other credentials.  IcedID can use a self signed TLS certificate in connection with the spoofed site and simultaneously maintains a live connection with the legitimate site to display the correct URL and certificates in the browser.

### S0530 - Melcoz

Melcoz can monitor the victim's browser for online banking sessions and display an overlay window to manipulate the session in the background.

### S0650 - QakBot

QakBot can use advanced web injects to steal web banking credentials.

### S1201 - TRANSLATEXT

TRANSLATEXT has the ability to use form-grabbing and event-listening to extract data from web data forms.

### S0266 - TrickBot

TrickBot uses web injects and browser redirection to trick the user into providing their login credentials on a fake or modified web page.

### S0386 - Ursnif

Ursnif has injected HTML codes into banking sites to steal sensitive online banking information (ex: usernames and passwords).

### S1207 - XLoader

XLoader can conduct form grabbing, steal cookies, and extract data from HTTP sessions.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
