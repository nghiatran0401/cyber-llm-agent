# T1674 - Input Injection

**Tactic:** Execution
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1674

## Description

Adversaries may simulate keystrokes on a victim’s computer by various means to perform any type of action on behalf of the user, such as launching the command interpreter using keyboard shortcuts,  typing an inline script to be executed, or interacting directly with a GUI-based application.  These actions can be preprogrammed into adversary tooling or executed through physical devices such as Human Interface Devices (HIDs).

For example, adversaries have used tooling that monitors the Windows message loop to detect when a user visits bank-specific URLs. If detected, the tool then simulates keystrokes to open the developer console or select the address bar, pastes malicious JavaScript from the clipboard, and executes it - enabling manipulation of content within the browser, such as replacing bank account numbers during transactions.

Adversaries have also used malicious USB devices to emulate keystrokes that launch PowerShell, leading to the download and execution of malware from adversary-controlled servers.

## Detection

### Detection Analytics

**Analytic 1567**

Detects suspicious USB HID device enumeration and keystroke injection patterns, such as rapid sequences of input with no user context, scripts executed through simulated keystrokes, or rogue devices presenting themselves as keyboards.

**Analytic 1568**

Detects USB HID device enumeration under `/sys/bus/usb/devices/` and rapid keystroke injection resulting in command execution such as bash or Python scripts launched without interactive user activity.

**Analytic 1569**

Detects abnormal HID device enumeration via I/O Registry (ioreg -p IOUSB) and keystroke injection targeting AppleScript, osascript, or PowerShell equivalents. Defender correlates new USB device connections with rapid script execution.


## Mitigations

### M1038 - Execution Prevention

Denylist scripting and use application control where appropriate. For example, PowerShell Constrained Language mode can be used to restrict access to sensitive or otherwise dangerous language elements such as those used to execute arbitrary Windows APIs or files (e.g., `Add-Type`).

### M1034 - Limit Hardware Installation

Limit the use of USB devices and removable media within a network.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
