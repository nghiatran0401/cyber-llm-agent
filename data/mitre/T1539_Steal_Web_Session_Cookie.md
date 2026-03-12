# T1539 - Steal Web Session Cookie

**Tactic:** Credential Access
**Platforms:** Linux, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1539

## Description

An adversary may steal web application or service session cookies and use them to gain access to web applications or Internet services as an authenticated user without needing credentials. Web applications and services often use session cookies as an authentication token after a user has authenticated to a website.

Cookies are often valid for an extended period of time, even if the web application is not actively used. Cookies can be found on disk, in the process memory of the browser, and in network traffic to remote systems. Additionally, other applications on the targets machine might store sensitive authentication cookies in memory (e.g. apps which authenticate to cloud services). Session cookies can be used to bypasses some multi-factor authentication protocols.

There are several examples of malware targeting cookies from web browsers on the local system. Adversaries may also steal cookies by injecting malicious JavaScript content into websites or relying on User Execution by tricking victims into running malicious JavaScript in their browser.

There are also open source frameworks such as `Evilginx2` and `Muraena` that can gather session cookies through a malicious proxy (e.g., Adversary-in-the-Middle) that can be set up by an adversary and used in phishing campaigns.

After an adversary acquires a valid cookie, they can then perform a Web Session Cookie technique to login to the corresponding web application.

## Detection

### Detection Analytics

**Analytic 1402**

Detects suspicious access to browser session cookie storage (e.g., Chrome’s `Cookies` SQLite DB) or memory reads of browser processes. Anomalous injection or memory dump utilities targeting browser processes such as `chrome.exe`, `firefox.exe`, or `msedge.exe`.

**Analytic 1403**

Detects access to known browser cookie files (e.g., `~/.mozilla/firefox/*.default/cookies.sqlite`, `~/.config/google-chrome/`) and suspicious reads of browser memory via `/proc/[pid]/mem` or ptrace.

**Analytic 1404**

Detects unauthorized access to browser cookie paths (e.g., `~/Library/Application Support/Google/Chrome/Default/Cookies`) or `task_for_pid`/`vm_read` calls to Safari/Chrome memory space.

**Analytic 1405**

Detects automation macros or VBA scripts in documents that access browser file paths, read cookie data, or attempt to exfiltrate browser session tokens over HTTP.

**Analytic 1406**

Detects use of session cookies or authentication tokens from unusual user agents or locations. Identifies token reuse without reauthentication or attempts to bypass MFA using previously stolen cookies.


## Mitigations

### M1047 - Audit

Implement auditing for authentication activities and user logins to detect the use of stolen session cookies. Monitor for impossible travel scenarios and anomalous behavior that could indicate the use of compromised session tokens or cookies.

### M1032 - Multi-factor Authentication

Deploy hardware-based token (e.g., YubiKey or FIDO key), which incorporates the target login domain as part of the negotiation protocol, will prevent session cookie theft through proxy methods.

Implement Conditional Access policies to only allow logins from trusted devices, such as those enrolled in Intune or joined via Hybrid/Entra. This mitigates the risk of session cookie replay attacks by ensuring that stolen tokens cannot be reused on unauthorized devices.

### M1021 - Restrict Web-Based Content

Restrict or block web-based content that could be used to extract session cookies or credentials stored in browsers. Use browser security settings, such as disabling third-party cookies and restricting browser extensions, to limit the attack surface.

### M1054 - Software Configuration

Configure browsers or tasks to regularly delete persistent cookies.

Additionally, minimize the length of time a web cookie is viable to potentially reduce the impact of stolen cookies while also increasing the needed frequency of cookie theft attempts – providing defenders with additional chances at detection. For example, use non-persistent cookies to limit the duration a session ID will remain on the web client cache where an attacker could obtain it.

### M1051 - Update Software

Regularly update web browsers, password managers, and all related software to the latest versions. Keeping software up-to-date reduces the risk of vulnerabilities being exploited by attackers to extract stored credentials or session cookies.

### M1017 - User Training

Train users to identify aspects of phishing attempts where they're asked to enter credentials into a site that has the incorrect domain for the application they are logging into. Additionally, train users not to run untrusted JavaScript in their browser, such as by copying and pasting code or dragging and dropping bookmarklets.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0657 - BLUELIGHT

BLUELIGHT can harvest cookies from Internet Explorer, Edge, Chrome, and Naver Whale browsers.

### S0631 - Chaes

Chaes has used a script that extracts the web session cookie and sends it to the C2 server.

### S0492 - CookieMiner

CookieMiner can steal Google Chrome and Apple Safari browser cookies from the victim’s machine.

### S1111 - DarkGate

DarkGate attempts to steal Opera cookies, if present, after terminating the related process.

### S0568 - EVILNUM

EVILNUM can harvest cookies and upload them to the C2 server.

### S0531 - Grandoreiro

Grandoreiro can steal the victim's cookies to use for duplicating the active session from another device.

### S1213 - Lumma Stealer

Lumma Stealer has harvested cookies from various browsers.

### S1146 - MgBot

MgBot includes modules that can steal cookies from Firefox, Chrome, and Edge web browsers.

### S0650 - QakBot

QakBot has the ability to capture web session cookies.

### S1148 - Raccoon Stealer

Raccoon Stealer attempts to steal cookies and related information in browser history.

### S1240 - RedLine Stealer

RedLine Stealer has stolen browser cookies and settings.

### S1140 - Spica

Spica has the ability to steal cookies from Chrome, Firefox, Opera, and Edge browsers.

### S1201 - TRANSLATEXT

TRANSLATEXT has exfiltrated updated cookies from Google, Naver, Kakao or Daum to the C2 server.

### S0467 - TajMahal

TajMahal has the ability to steal web session cookies from Internet Explorer, Netscape Navigator, FireFox and RealNetworks applications.

### S0658 - XCSSET

XCSSET uses <code>scp</code> to access the <code>~/Library/Cookies/Cookies.binarycookies</code> file.

### S1207 - XLoader

XLoader can capture web session cookies and session information from victim browsers.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0024 - SolarWinds Compromise

During the SolarWinds Compromise, APT29 stole Chrome browser cookies by copying the Chrome profile directories of targeted users.
