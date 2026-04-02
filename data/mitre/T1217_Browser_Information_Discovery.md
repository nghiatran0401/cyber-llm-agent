# T1217 - Browser Information Discovery

**Tactic:** Discovery
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1217

## Description

Adversaries may enumerate information about browsers to learn more about compromised environments. Data saved by browsers (such as bookmarks, accounts, and browsing history) may reveal a variety of personal information about users (e.g., banking sites, relationships/interests, social media, etc.) as well as details about internal network resources such as servers, tools/dashboards, or other related infrastructure.

Browser information may also highlight additional targets after an adversary has access to valid credentials, especially Credentials In Files associated with logins cached by a browser.

Specific storage locations vary based on platform and/or application, but browser information is typically stored in local files and databases (e.g., `%APPDATA%/Google/Chrome`).

## Detection

### Detection Analytics

**Analytic 0037**

Access to browser artifact locations (e.g., Chrome, Edge, Firefox) by processes like PowerShell, cmd.exe, or unknown tools, followed by file reads, decoding, or export operations indicating enumeration of bookmarks, autofill, or history databases.

**Analytic 0038**

Unauthorized shell or script-based access to browser config or SQLite history files, typically in ~/.config/google-chrome/, ~/.mozilla/, or ~/.var/app folders, indicating enumeration of bookmarks or saved credentials.

**Analytic 0039**

Scripting or CLI tool access to ~/Library/Application Support/Google/Chrome or ~/Library/Safari bookmarks, cookies, or history databases. Detection relies on unexpected processes accessing or reading from these locations.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1246 - BeaverTail

BeaverTail has searched the victim device for browser extensions including those commonly associated with cryptocurrency wallets.

### S0274 - Calisto

Calisto collects information on bookmarks from Google Chrome.

### S1153 - Cuckoo Stealer

Cuckoo Stealer can collect bookmarks, cookies, and history from Safari.

### S0673 - DarkWatchman

DarkWatchman can retrieve browser history.

### S0567 - Dtrack

Dtrack can retrieve browser history.

### S0363 - Empire

Empire has the ability to gather browser data such as bookmarks and visited sites.

### S1185 - LightSpy

To collect data on the host's Wi-Fi connection history, LightSpy reads the `/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist` file. It also utilizes Apple's `CWWiFiClient` API to scan for nearby Wi-Fi networks and obtain data on the SSID, security type, and RSSI (signal strength) values.

### S0681 - Lizar

Lizar can retrieve browser history and database files.

### S1213 - Lumma Stealer

Lumma Stealer has identified and gathered information from two-factor authentication extensions for multiple browsers.

### S0409 - Machete

Machete retrieves the user profile data (e.g., browsers) from Chrome and Firefox browsers.

### S1060 - Mafalda

Mafalda can collect the contents of the `%USERPROFILE%\AppData\Local\Google\Chrome\User Data\LocalState` file.

### S1122 - Mispadu

Mispadu can monitor browser activity for online banking actions and display full-screen overlay images to block user access to the intended site or present additional data fields.

### S0079 - MobileOrder

MobileOrder has a command to upload to its C2 server victim browser bookmarks.

### S1012 - PowerLess

PowerLess has a browser info stealer module that can read Chrome and Edge browser database files.

### S1240 - RedLine Stealer

RedLine Stealer can collect information from browsers and browser extensions.

### S1042 - SUGARDUMP

SUGARDUMP has collected browser bookmark and history information.

### S1196 - Troll Stealer

Troll Stealer collects information from Chromium-based browsers and Firefox such as cookies, history, downloads, and extensions.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0057 - 3CX Supply Chain Attack

During the 3CX Supply Chain Attack, AppleJeus leveraged ICONICSTEALER to steal browser information to include browser history located on the infected host.

### C0044 - Juicy Mix

During Juicy Mix, OilRig used the CDumper (Chrome browser) and EDumper (Edge browser) data stealers to collect cookies, browsing history, and credentials.

### C0042 - Outer Space

During Outer Space, OilRig used a Chrome data dumper named MKG.
