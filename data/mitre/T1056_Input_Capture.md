# T1056 - Input Capture

**Tactic:** Collection, Credential Access
**Platforms:** Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1056

## Description

Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g. Credential API Hooking) or rely on deceiving the user into providing input into what they believe to be a genuine service (e.g. Web Portal Capture).

## Detection

### Detection Analytics

**Analytic 0282**

Monitors for abnormal process behavior and API calls like SetWindowsHookEx, GetAsyncKeyState, or device input polling commonly used for keystroke logging.

**Analytic 0283**

Detects use of tools/scripts accessing input devices like /dev/input/* or evdev via suspicious processes lacking GUI context.

**Analytic 0284**

Monitors for TCC-bypassing or unauthorized access to input services like IOHIDSystem or Quartz Event Services used in keylogging or screen monitoring.

**Analytic 0285**

Detects web-based credential phishing by analyzing traffic to suspicious URLs that mimic login portals and POST credential content.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0631 - Chaes

Chaes has a module to perform any API hooking it desires.

### S0381 - FlawedAmmyy

FlawedAmmyy can collect mouse events.

### S1245 - InvisibleFerret

InvisibleFerret has collected mouse and keyboard events using “pyWinhook”.

### S0641 - Kobalos

Kobalos has used a compromised SSH client to capture the hostname, port, username and password used to establish an SSH connection from the compromised host.

### S1060 - Mafalda

Mafalda can conduct mouse event logging.

### S1131 - NPPSPY

NPPSPY captures user input into the Winlogon process by redirecting RPC traffic from legitimate listening DLLs within the operating system to a newly registered malicious item that allows for recording logon information in cleartext.

### S1059 - metaMain

metaMain can log mouse events.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0049 - Leviathan Australian Intrusions

Leviathan captured submitted multfactor authentication codes and other technical artifacts related to remote access sessions during Leviathan Australian Intrusions.

### C0039 - Versa Director Zero Day Exploitation

Versa Director Zero Day Exploitation intercepted and harvested credentials from user logins to compromised devices.
