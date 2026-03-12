# T1011 - Exfiltration Over Other Network Medium

**Tactic:** Exfiltration
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1011

## Description

Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel. If the command and control network is a wired Internet connection, the exfiltration may occur, for example, over a WiFi connection, modem, cellular data connection, Bluetooth, or another radio frequency (RF) channel.

Adversaries may choose to do this if they have sufficient access or proximity, and the connection might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network.

## Detection

### Detection Analytics

**Analytic 0212**

Execution of file transfer or network access activity through non-primary interfaces (e.g., WiFi, Bluetooth, cellular) by processes not typically associated with such behavior (e.g., rundll32, powershell, regsvr32).

**Analytic 0213**

Use of `rfkill`, `nmcli`, or low-level tools (e.g., `iw`, `hcitool`, `pppd`) to enable alternate interfaces followed by data transfer via non-primary NICs.

**Analytic 0214**

AppleScript or system calls to activate WiFi/Bluetooth interfaces (`networksetup`, `blueutil`), followed by exfiltration via AirDrop, cloud sync, or network socket.


## Mitigations

### M1042 - Disable or Remove Feature or Program

Disable WiFi connection, modem, cellular data connection, Bluetooth, or another radio frequency (RF) channel in local computer security settings or by group policy if it is not needed within an environment.

### M1028 - Operating System Configuration

Prevent the creation of new network adapters where possible.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
